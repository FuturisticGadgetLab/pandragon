"""
Minimal Task Queue

Tracks pending tasks for beacons. No scheduler, no cron, no retries.
Tasks execute immediately when added.
"""

import time
import asyncio
import threading
import logging
from typing import Optional, Dict, List, Callable, Any
from dataclasses import dataclass, field
from enum import IntEnum

logger = logging.getLogger('pandragon.taskqueue')


class TaskState(IntEnum):
    PENDING = 0
    QUEUED = 1
    COMPLETED = 2
    FAILED = 3
    CANCELLED = 4


@dataclass
class ScheduledTask:
    task_id: str
    beacon_id: str
    opcode: int
    payload: bytes = b""
    state: TaskState = TaskState.PENDING
    operator_id: Optional[str] = None
    description: str = ""
    created_at: float = field(default_factory=time.time)
    result: Any = None
    error: Optional[str] = None


class TaskQueue:
    def __init__(self):
        self._tasks: Dict[str, ScheduledTask] = {}
        self._beacon_tasks: Dict[str, List[str]] = {}
        self._lock = asyncio.Lock()
        self._task_callback: Optional[Callable] = None
        self._completion_callback: Optional[Callable] = None
        self._task_counter = 0
        self._task_counter_lock = threading.Lock()

    async def start(self, task_callback=None, completion_callback=None):
        """Register callbacks. No background thread needed."""
        self._task_callback = task_callback
        self._completion_callback = completion_callback

    async def stop(self):
        """No-op. Tasks execute inline on add."""
        pass

    def _next_task_id(self) -> str:
        with self._task_counter_lock:
            self._task_counter += 1
            return f"task_{self._task_counter}_{int(time.time())}"

    async def add_task(self, beacon_id: str, opcode: int, payload: bytes = b"",
                       operator_id: Optional[str] = None,
                       description: str = "") -> str:
        task_id = self._next_task_id()
        async with self._lock:
            task = ScheduledTask(
                task_id=task_id,
                beacon_id=beacon_id,
                opcode=opcode,
                payload=payload,
                operator_id=operator_id,
                description=description,
            )
            self._tasks[task_id] = task
            self._beacon_tasks.setdefault(beacon_id, []).append(task_id)

        if self._task_callback:
            try:
                await self._task_callback(task_id, beacon_id, opcode, payload)
                async with self._lock:
                    task.state = TaskState.QUEUED
            except Exception as e:
                logger.error(f"Task execution error for {task_id}: {e}")
                async with self._lock:
                    task.state = TaskState.FAILED
                    task.error = str(e)

        logger.debug(f"Task {task_id} added for beacon {beacon_id} (opcode={opcode:#04x})")
        return task_id

    async def complete_task(self, task_id: str, result: Any = None, error: Optional[str] = None) -> None:
        async with self._lock:
            task = self._tasks.get(task_id)
            if not task:
                logger.warning(f"Cannot complete unknown task {task_id}")
                return

            if error:
                task.state = TaskState.FAILED
                task.error = error
            else:
                task.state = TaskState.COMPLETED
                task.result = result

        if self._completion_callback:
            try:
                self._completion_callback(task_id, task.state, result, error)
            except Exception as e:
                logger.error(f"Completion callback error: {e}")

    async def cancel_task(self, task_id: str) -> bool:
        async with self._lock:
            task = self._tasks.get(task_id)
            if not task or task.state not in (TaskState.PENDING,):
                return False
            task.state = TaskState.CANCELLED
            return True

    def get_task(self, task_id: str) -> Optional[ScheduledTask]:
        return self._tasks.get(task_id)

    async def get_beacon_tasks(self, beacon_id: str, state: Optional[TaskState] = None) -> List[ScheduledTask]:
        async with self._lock:
            task_ids = self._beacon_tasks.get(beacon_id, [])
            result = [self._tasks[tid] for tid in task_ids if tid in self._tasks]
            if state is not None:
                result = [t for t in result if t.state == state]
            return list(result)

    async def list_tasks(self, beacon_id: Optional[str] = None,
                         state: Optional[TaskState] = None) -> List[Dict]:
        async with self._lock:
            tasks = []
            for task in self._tasks.values():
                if beacon_id and task.beacon_id != beacon_id:
                    continue
                if state and task.state != state:
                    continue
                tasks.append(self._task_to_dict(task))
            return tasks

    @staticmethod
    def _task_to_dict(task: ScheduledTask) -> Dict:
        return {
            'task_id': task.task_id,
            'beacon_id': task.beacon_id,
            'opcode': task.opcode,
            'state': task.state.name,
            'error': task.error,
            'created_at': task.created_at,
            'operator_id': task.operator_id,
            'description': task.description,
            'result_preview': str(task.result)[:500] if task.result else None,
        }
