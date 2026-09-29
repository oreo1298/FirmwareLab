"""Background workers so parsing and saving never freeze the UI thread.

The completion callbacks MUST be bound methods of a QObject that lives in the GUI
thread (e.g. the main window). Qt then auto-queues signal delivery onto that thread,
so the slots run on the GUI thread even though the work ran on a worker thread.
"""

from __future__ import annotations

from PySide6.QtCore import QObject, QThread, Signal

from ..formats.context import ParseOptions
from ..tools.project import Document


class OpenWorker(QObject):
    done = Signal(object, str)   # Document, path
    failed = Signal(str, str)    # message, path

    def __init__(self, path: str, options: ParseOptions | None = None):
        super().__init__()
        self.path = path
        self.options = options

    def run(self):
        try:
            doc = Document.open(self.path, self.options)
        except Exception as e:  # noqa: BLE001 - surfaced to the user
            self.failed.emit("%s: %s" % (type(e).__name__, e), self.path)
            return
        self.done.emit(doc, self.path)


class SaveWorker(QObject):
    done = Signal(object, str)   # VerifyReport, path
    failed = Signal(str, str)    # message, path

    def __init__(self, doc: Document, path: str, backup: bool = True, verify: bool = True):
        super().__init__()
        self.doc = doc
        self.path = path
        self.backup = backup
        self.verify = verify

    def run(self):
        try:
            rep = self.doc.save(self.path, backup=self.backup, verify=self.verify, reload=True)
        except Exception as e:  # noqa: BLE001
            self.failed.emit("%s: %s" % (type(e).__name__, e), self.path)
            return
        self.done.emit(rep, self.path)


def run_async(parent, worker: QObject, on_done, on_failed):
    """Run ``worker.run`` on a QThread; deliver results to bound-method slots.

    ``on_done`` / ``on_failed`` must be bound methods of a GUI-thread QObject so Qt
    queues them onto the GUI thread. The QThread lives in ``parent``'s thread, so its
    ``finished`` signal is delivered there too, where cleanup happens safely.
    """
    thread = QThread(parent)
    thread._worker = worker  # keep a Python reference so the worker is not GC'd mid-run
    worker.moveToThread(thread)
    thread.started.connect(worker.run)

    # Delivered on the GUI thread (receivers are GUI-thread QObjects).
    worker.done.connect(on_done)
    worker.failed.connect(on_failed)
    # Thread-safe: ask the thread to stop once work is reported.
    worker.done.connect(thread.quit)
    worker.failed.connect(thread.quit)
    # Cleanup runs on the GUI thread via the queued finished signal — no wait().
    thread.finished.connect(worker.deleteLater)
    thread.finished.connect(thread.deleteLater)

    if not hasattr(parent, "_threads"):
        parent._threads = []
    parent._threads.append(thread)
    thread.finished.connect(lambda: parent._threads.remove(thread) if thread in parent._threads else None)
    thread.start()
    return thread
