"""
P2P Beacon Relay Routing Module

Manages relay routing graph for P2P beacon chaining.
Parent beacons act as dumb relays - they never decrypt child traffic.
Server maintains the full routing graph and handles multi-hop support.
"""

import time
import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger('pandragon.relay_routing')


@dataclass
class BeaconRoute:
    """
    Represents a route to a beacon (direct or relayed).
    
    Attributes:
        beacon_id: 8-byte beacon identifier
        transport: "direct" | "relay"
        via_beacon_id: Parent's beacon_id (for relay transport)
        parent_pipe_id: Parent's local pipe_id (for relay transport)
        depth: Hop count (0 = direct, 1 = relayed once, etc.)
        last_seen: Last activity timestamp
        is_alive: Whether beacon is considered alive
        metadata: Optional metadata (IP, OS, etc.) for GUI visualization
    """
    beacon_id: bytes
    transport: str  # "direct" | "relay"
    via_beacon_id: Optional[bytes] = None
    parent_pipe_id: Optional[int] = None
    depth: int = 0
    last_seen: float = field(default_factory=time.time)
    is_alive: bool = True
    metadata: Dict = field(default_factory=dict)
    
    def to_dict(self) -> dict:
        """Convert to dictionary for JSON serialization."""
        return {
            'beacon_id': self.beacon_id.hex() if self.beacon_id else None,
            'transport': self.transport,
            'via_beacon_id': self.via_beacon_id.hex() if self.via_beacon_id else None,
            'parent_pipe_id': self.parent_pipe_id,
            'depth': self.depth,
            'last_seen': self.last_seen,
            'is_alive': self.is_alive,
            'metadata': self.metadata
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> 'BeaconRoute':
        """Create from dictionary."""
        beacon_id = bytes.fromhex(data['beacon_id']) if data.get('beacon_id') else None
        via_id = bytes.fromhex(data['via_beacon_id']) if data.get('via_beacon_id') else None
        return cls(
            beacon_id=beacon_id,
            transport=data.get('transport', 'direct'),
            via_beacon_id=via_id,
            parent_pipe_id=data.get('parent_pipe_id'),
            depth=data.get('depth', 0),
            last_seen=data.get('last_seen', time.time()),
            is_alive=data.get('is_alive', True),
            metadata=data.get('metadata', {})
        )


class RelayRoutingManager:
    """
    Manages P2P beacon relay routing graph.
    
    Maintains:
    - routes: beacon_id -> BeaconRoute mapping
    - relay_children: parent_beacon_id -> [child_beacon_id, ...]
    - pipe_id_to_child: (parent_beacon_id, pipe_id) -> child_beacon_id
    
    When a parent disconnects:
    1. Mark parent offline
    2. For each child in relay_children[parent_id]: mark offline
    3. Optionally: attempt re-parenting if other parents available
    """
    
    def __init__(self):
        # beacon_id -> BeaconRoute
        self.routes: Dict[bytes, BeaconRoute] = {}
        # parent_beacon_id -> [child_beacon_id, ...]
        self.relay_children: Dict[bytes, List[bytes]] = {}
        # (parent_beacon_id, pipe_id) -> child_beacon_id
        self.pipe_id_to_child: Dict[Tuple[bytes, int], bytes] = {}
        # Reverse mapping: child_beacon_id -> (parent_beacon_id, pipe_id)
        self.child_to_parent: Dict[bytes, Tuple[bytes, int]] = {}
        # Pipe name -> pipe_id mapping for parent beacons
        self.pipe_names: Dict[bytes, Dict[str, int]] = {}  # beacon_id -> {pipe_name: pipe_id}
        
    # =========================================================================
    # Route Management
    # =========================================================================
    
    def add_route(self, beacon_id: bytes, route: BeaconRoute) -> bool:
        """
        Add or update a beacon route.
        
        Args:
            beacon_id: 8-byte beacon identifier
            route: BeaconRoute instance
            
        Returns:
            True if added/updated, False on error
        """
        if not beacon_id or len(beacon_id) != 8:
            logger.error(f"Invalid beacon_id: {beacon_id!r}")
            return False
        
        self.routes[beacon_id] = route
        logger.debug(f"Added route for beacon {beacon_id.hex()}: {route.transport}")
        return True
    
    def create_route(self, beacon_id: bytes, via_beacon_id: bytes, 
                     parent_pipe_id: int) -> BeaconRoute:
        """
        Create and add a relay route for a beacon.
        
        Args:
            beacon_id: Child beacon's ID
            via_beacon_id: Parent beacon's ID
            parent_pipe_id: Parent's local pipe ID
            
        Returns:
            Created BeaconRoute instance
        """
        route = BeaconRoute(
            beacon_id=beacon_id,
            transport='relay',
            via_beacon_id=via_beacon_id,
            parent_pipe_id=parent_pipe_id,
            depth=1  # Direct child is depth 1
        )
        
        self.add_route(beacon_id, route)
        self.add_relay_child(via_beacon_id, beacon_id, parent_pipe_id)
        
        return route
    
    def get_route(self, beacon_id: bytes) -> Optional[BeaconRoute]:
        """Get route for a beacon, or None if not found."""
        return self.routes.get(beacon_id)
    
    def remove_route(self, beacon_id: bytes) -> bool:
        """
        Remove a beacon route and clean up associated mappings.
        
        Args:
            beacon_id: 8-byte beacon identifier
            
        Returns:
            True if removed, False if not found
        """
        if beacon_id not in self.routes:
            return False
        
        # Remove from relay_children if this is a parent
        if beacon_id in self.relay_children:
            del self.relay_children[beacon_id]
        
        # Remove pipe_id_to_child mappings
        keys_to_remove = [
            key for key in self.pipe_id_to_child 
            if key[0] == beacon_id
        ]
        for key in keys_to_remove:
            del self.pipe_id_to_child[key]
        
        # Remove from child_to_parent
        if beacon_id in self.child_to_parent:
            parent_id, pipe_id = self.child_to_parent[beacon_id]
            del self.child_to_parent[beacon_id]
            if (parent_id, pipe_id) in self.pipe_id_to_child:
                del self.pipe_id_to_child[(parent_id, pipe_id)]
        
        # Remove pipe names
        if beacon_id in self.pipe_names:
            del self.pipe_names[beacon_id]
        
        del self.routes[beacon_id]
        logger.debug(f"Removed route for beacon {beacon_id.hex()}")
        return True
    
    def update_last_seen(self, beacon_id: bytes):
        """Update last_seen timestamp for a beacon."""
        if beacon_id in self.routes:
            self.routes[beacon_id].last_seen = time.time()
            self.routes[beacon_id].is_alive = True
    
    # =========================================================================
    # Relay Child Management
    # =========================================================================
    
    def add_relay_child(self, parent_beacon_id: bytes, child_beacon_id: bytes, 
                        pipe_id: int) -> bool:
        """
        Add a child beacon to a parent's relay list.
        
        Args:
            parent_beacon_id: Parent beacon's ID
            child_beacon_id: Child beacon's ID
            pipe_id: Parent's local pipe_id for this child
            
        Returns:
            True if added, False on error
        """
        if parent_beacon_id not in self.relay_children:
            self.relay_children[parent_beacon_id] = []
        
        if child_beacon_id not in self.relay_children[parent_beacon_id]:
            self.relay_children[parent_beacon_id].append(child_beacon_id)
        
        # Map (parent, pipe_id) -> child
        self.pipe_id_to_child[(parent_beacon_id, pipe_id)] = child_beacon_id
        # Reverse mapping
        self.child_to_parent[child_beacon_id] = (parent_beacon_id, pipe_id)
        
        logger.debug(f"Added relay child {child_beacon_id.hex()} to parent "
                     f"{parent_beacon_id.hex()} (pipe_id={pipe_id})")
        return True
    
    def remove_relay_child(self, parent_beacon_id: bytes, 
                           child_beacon_id: bytes) -> bool:
        """
        Remove a child beacon from a parent's relay list.
        
        Args:
            parent_beacon_id: Parent beacon's ID
            child_beacon_id: Child beacon's ID
            
        Returns:
            True if removed, False if not found
        """
        if parent_beacon_id not in self.relay_children:
            return False
        
        if child_beacon_id in self.relay_children[parent_beacon_id]:
            self.relay_children[parent_beacon_id].remove(child_beacon_id)
        
        # Remove from child_to_parent and get pipe_id
        if child_beacon_id in self.child_to_parent:
            parent_id, pipe_id = self.child_to_parent[child_beacon_id]
            del self.child_to_parent[child_beacon_id]
            if (parent_id, pipe_id) in self.pipe_id_to_child:
                del self.pipe_id_to_child[(parent_id, pipe_id)]
        
        logger.debug(f"Removed relay child {child_beacon_id.hex()} from parent "
                     f"{parent_beacon_id.hex()}")
        return True
    
    def get_children(self, parent_beacon_id: bytes) -> List[bytes]:
        """Get list of child beacon IDs for a parent."""
        return self.relay_children.get(parent_beacon_id, []).copy()
    
    def get_parent(self, child_beacon_id: bytes) -> Optional[Tuple[bytes, int]]:
        """
        Get parent info for a child beacon.
        
        Returns:
            (parent_beacon_id, pipe_id) or None if not relayed
        """
        return self.child_to_parent.get(child_beacon_id)
    
    def get_child_by_pipe_id(self, parent_beacon_id: bytes, 
                             pipe_id: int) -> Optional[bytes]:
        """Get child beacon ID for a given (parent, pipe_id)."""
        return self.pipe_id_to_child.get((parent_beacon_id, pipe_id))
    
    # =========================================================================
    # Pipe Name Management
    # =========================================================================
    
    def add_pipe_name(self, beacon_id: bytes, pipe_name: str, 
                      pipe_id: int) -> bool:
        """
        Add a pipe name mapping for a beacon.
        
        Args:
            beacon_id: Parent beacon's ID
            pipe_name: Name of the pipe (e.g., "msagent_XYZ")
            pipe_id: Local pipe ID
            
        Returns:
            True if added, False on error
        """
        if beacon_id not in self.pipe_names:
            self.pipe_names[beacon_id] = {}
        
        self.pipe_names[beacon_id][pipe_name] = pipe_id
        logger.debug(f"Added pipe name {pipe_name} (id={pipe_id}) for beacon "
                     f"{beacon_id.hex()}")
        return True
    
    def get_pipe_id(self, beacon_id: bytes, pipe_name: str) -> Optional[int]:
        """Get pipe_id for a given beacon and pipe name."""
        if beacon_id in self.pipe_names:
            return self.pipe_names[beacon_id].get(pipe_name)
        return None
    
    def remove_pipe_name(self, beacon_id: bytes, pipe_name: str) -> bool:
        """Remove a pipe name mapping."""
        if beacon_id in self.pipe_names:
            if pipe_name in self.pipe_names[beacon_id]:
                del self.pipe_names[beacon_id][pipe_name]
                return True
        return False
    
    # =========================================================================
    # Parent Disconnect Handling
    # =========================================================================
    
    def handle_parent_disconnect(self, parent_beacon_id: bytes) -> List[bytes]:
        """
        Handle parent beacon disconnect - mark all children as offline.
        
        Args:
            parent_beacon_id: Parent beacon's ID
            
        Returns:
            List of child beacon IDs that were marked offline
        """
        offline_children = []
        
        if parent_beacon_id in self.relay_children:
            for child_id in self.relay_children[parent_beacon_id].copy():
                if child_id in self.routes:
                    self.routes[child_id].is_alive = False
                    self.routes[child_id].last_seen = time.time()
                offline_children.append(child_id)
                logger.debug(f"Marked child {child_id.hex()} offline due to "
                             f"parent {parent_beacon_id.hex()} disconnect")
            
            # Clear children list
            del self.relay_children[parent_beacon_id]
        
        return offline_children
    
    # =========================================================================
    # Graph Visualization Support
    # =========================================================================
    
    def get_relay_graph(self) -> dict:
        """
        Get the relay graph as a dictionary for visualization.
        
        Returns:
            Dictionary representation of the relay graph
        """
        graph = {
            'nodes': [],
            'edges': []
        }
        
        # Add all routes as nodes
        for beacon_id, route in self.routes.items():
            node = {
                'id': beacon_id.hex(),
                'transport': route.transport,
                'depth': route.depth,
                'is_alive': route.is_alive,
                'last_seen': route.last_seen,
                'metadata': route.metadata
            }
            graph['nodes'].append(node)
            
            # Add edge for relayed beacons
            if route.transport == 'relay' and route.via_beacon_id:
                edge = {
                    'from': route.via_beacon_id.hex(),
                    'to': beacon_id.hex(),
                    'pipe_id': route.parent_pipe_id
                }
                graph['edges'].append(edge)
        
        return graph
    
    def to_dict(self) -> dict:
        """Convert entire routing state to dictionary."""
        return {
            'routes': {k.hex(): v.to_dict() for k, v in self.routes.items()},
            'relay_children': {
                k.hex(): [c.hex() for c in v] 
                for k, v in self.relay_children.items()
            },
            'pipe_id_to_child': {
                f"{k[0].hex()}:{k[1]}": v.hex() 
                for k, v in self.pipe_id_to_child.items()
            },
            'child_to_parent': {
                k.hex(): f"{v[0].hex()}:{v[1]}" 
                for k, v in self.child_to_parent.items()
            },
            'pipe_names': {
                k.hex(): v for k, v in self.pipe_names.items()
            }
        }
    
    @classmethod
    def from_dict(cls, data: dict) -> 'RelayRoutingManager':
        """Create from dictionary."""
        manager = cls()
        
        # Restore routes
        for beacon_hex, route_data in data.get('routes', {}).items():
            beacon_id = bytes.fromhex(beacon_hex)
            route = BeaconRoute.from_dict(route_data)
            manager.routes[beacon_id] = route
        
        # Restore relay_children
        for parent_hex, children in data.get('relay_children', {}).items():
            parent_id = bytes.fromhex(parent_hex)
            manager.relay_children[parent_id] = [
                bytes.fromhex(c) for c in children
            ]
        
        # Restore pipe_id_to_child
        for key_str, child_hex in data.get('pipe_id_to_child', {}).items():
            parent_hex, pipe_id_str = key_str.split(':')
            pipe_id = int(pipe_id_str)
            parent_id = bytes.fromhex(parent_hex)
            child_id = bytes.fromhex(child_hex)
            manager.pipe_id_to_child[(parent_id, pipe_id)] = child_id
        
        # Restore child_to_parent
        for child_hex, value_str in data.get('child_to_parent', {}).items():
            parent_hex, pipe_id_str = value_str.split(':')
            child_id = bytes.fromhex(child_hex)
            parent_id = bytes.fromhex(parent_hex)
            pipe_id = int(pipe_id_str)
            manager.child_to_parent[child_id] = (parent_id, pipe_id)
        
        # Restore pipe_names
        for beacon_hex, names in data.get('pipe_names', {}).items():
            beacon_id = bytes.fromhex(beacon_hex)
            manager.pipe_names[beacon_id] = names
        
        return manager


# Global instance for easy access
_relay_manager: Optional[RelayRoutingManager] = None


def get_relay_manager() -> RelayRoutingManager:
    """Get or create the global relay routing manager instance."""
    global _relay_manager
    if _relay_manager is None:
        _relay_manager = RelayRoutingManager()
    return _relay_manager


def reset_relay_manager():
    """Reset the global relay manager (for testing)."""
    global _relay_manager
    _relay_manager = None