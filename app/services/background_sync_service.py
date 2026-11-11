"""
Background Sync Service

Runs bulk CVE sync operations in the background with progress tracking.
Supports pause, resume, and cancel operations.
"""

import threading
from datetime import datetime
from typing import Optional
from sqlalchemy.orm import Session

from app.models.background_task import BackgroundTask
from app.models.component import Component
from app.services.nvd_service import nvd_service


class BackgroundSyncService:
    """Service for running background tasks with progress tracking."""

    def __init__(self):
        self.active_tasks = {}  # task_id -> thread
        self.pause_flags = {}  # task_id -> bool (pause flag)
        self.cancel_flags = {}  # task_id -> bool (cancel flag)

    def start_bulk_cve_sync(
        self,
        db: Session,
        application_id: Optional[int] = None,
        username: str = "system"
    ) -> BackgroundTask:
        """
        Start a bulk CVE sync in the background.

        Args:
            db: Database session
            application_id: Optional application ID to filter components
            username: Username who started the task

        Returns:
            BackgroundTask object with task ID
        """
        # Get component IDs to sync (not objects to avoid session issues)
        query = db.query(Component.id)
        if application_id:
            query = query.filter(Component.application_id == application_id)

        component_ids = [id for (id,) in query.all()]

        if not component_ids:
            raise ValueError("No components found to sync")

        # Create task record
        task = BackgroundTask(
            task_type="bulk_cve_sync",
            status="pending",
            total_items=len(component_ids),
            processed_items=0,
            failed_items=0,
            created_by=username
        )
        db.add(task)
        db.commit()
        db.refresh(task)

        # Start background thread
        thread = threading.Thread(
            target=self._run_bulk_sync,
            args=(task.id, component_ids, application_id, username)
        )
        thread.daemon = True
        thread.start()

        self.active_tasks[task.id] = thread
        self.pause_flags[task.id] = False
        self.cancel_flags[task.id] = False

        return task

    def pause_task(self, db: Session, task_id: int) -> bool:
        """Pause a running task."""
        task = db.query(BackgroundTask).filter(BackgroundTask.id == task_id).first()
        if not task or task.status != "running":
            return False
        
        self.pause_flags[task_id] = True
        task.status = "paused"
        db.commit()
        return True

    def resume_task(self, db: Session, task_id: int) -> bool:
        """Resume a paused task."""
        task = db.query(BackgroundTask).filter(BackgroundTask.id == task_id).first()
        if not task or task.status != "paused":
            return False
        
        self.pause_flags[task_id] = False
        task.status = "running"
        db.commit()
        return True

    def cancel_task(self, db: Session, task_id: int) -> bool:
        """Cancel a running or paused task."""
        task = db.query(BackgroundTask).filter(BackgroundTask.id == task_id).first()
        if not task or task.status not in ["running", "paused"]:
            return False
        
        self.cancel_flags[task_id] = True
        task.status = "cancelled"
        db.commit()
        return True

    def _run_bulk_sync(
        self,
        task_id: int,
        component_ids: list,
        application_id: Optional[int],
        username: str
    ):
        """
        Run the bulk sync in a background thread.
        Updates progress in the database as it goes.
        """
        from app.core.database import SessionLocal

        db = SessionLocal()

        try:
            # Mark task as running
            task = db.query(BackgroundTask).filter(BackgroundTask.id == task_id).first()
            if not task:
                return

            task.status = "running"
            task.started_at = datetime.utcnow()
            db.commit()

            results = {
                "total": len(component_ids),
                "processed": 0,
                "failed": 0,
                "details": []
            }

            for component_id in component_ids:
                # Check for cancel flag
                if self.cancel_flags.get(task_id, False):
                    task.status = "cancelled"
                    task.completed_at = datetime.utcnow()
                    task.current_item = None
                    db.commit()
                    print(f"[Background Sync] Task cancelled by user")
                    return
                
                # Check for pause flag
                while self.pause_flags.get(task_id, False):
                    import time
                    time.sleep(0.5)
                    # Re-check cancel while paused
                    if self.cancel_flags.get(task_id, False):
                        task.status = "cancelled"
                        task.completed_at = datetime.utcnow()
                        task.current_item = None
                        db.commit()
                        print(f"[Background Sync] Task cancelled while paused")
                        return
                
                try:
                    # Fetch fresh component from new session
                    component = db.query(Component).filter(Component.id == component_id).first()
                    if not component:
                        results["failed"] += 1
                        task.failed_items += 1
                        results["details"].append({
                            "component_id": component_id,
                            "status": "failed",
                            "error": "Component not found"
                        })
                        continue

                    # Update current item
                    task.current_item = f"{component.name} {component.version}"
                    db.commit()

                    # Sync CVEs for this component
                    cves = nvd_service.sync_component_cves(db, component)

                    results["processed"] += 1
                    task.processed_items += 1

                    results["details"].append({
                        "component_id": component.id,
                        "name": component.name,
                        "version": component.version,
                        "cves_found": len(cves),
                        "status": "success"
                    })

                    print(f"[Background Sync] {results['processed']}/{results['total']}: {component.name} {component.version} - {len(cves)} CVEs")

                except Exception as e:
                    results["failed"] += 1
                    task.failed_items += 1

                    results["details"].append({
                        "component_id": component_id,
                        "status": "failed",
                        "error": str(e)
                    })

                    print(f"[Background Sync] Failed for component_id {component_id}: {e}")

                # Update progress
                db.commit()

            # Mark task as completed
            task.status = "completed"
            task.completed_at = datetime.utcnow()
            task.current_item = None
            task.result = results
            db.commit()

            print(f"[Background Sync] Completed: {results['processed']} processed, {results['failed']} failed")

        except Exception as e:
            # Mark task as failed
            task = db.query(BackgroundTask).filter(BackgroundTask.id == task_id).first()
            if task:
                task.status = "failed"
                task.completed_at = datetime.utcnow()
                task.error_message = str(e)
                db.commit()

            print(f"[Background Sync] Task {task_id} failed: {e}")

        finally:
            db.close()
            # Remove from active tasks
            if task_id in self.active_tasks:
                del self.active_tasks[task_id]

    def get_task_status(self, db: Session, task_id: int) -> Optional[dict]:
        """Get the current status of a background task."""
        task = db.query(BackgroundTask).filter(BackgroundTask.id == task_id).first()
        if not task:
            return None
        return task.to_dict()

    def get_recent_tasks(
        self,
        db: Session,
        task_type: Optional[str] = None,
        limit: int = 10
    ) -> list:
        """Get recent background tasks."""
        query = db.query(BackgroundTask)
        if task_type:
            query = query.filter(BackgroundTask.task_type == task_type)

        tasks = query.order_by(BackgroundTask.created_at.desc()).limit(limit).all()
        return [task.to_dict() for task in tasks]


# Singleton
background_sync_service = BackgroundSyncService()
