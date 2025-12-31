import logging
import threading
from contextlib import contextmanager
from pathlib import Path

def _get_console_logger():
    console_logger = logging.getLogger("console")
    if not console_logger.handlers:
        handler = logging.StreamHandler()
        handler.setLevel(logging.INFO)
        handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        console_logger.addHandler(handler)
        console_logger.setLevel(logging.INFO)
        console_logger.propagate = False
    return console_logger


def _configure_parallel_logging():
    root = logging.getLogger()
    for handler in list(root.handlers):
        root.removeHandler(handler)
    root.setLevel(logging.DEBUG)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.ERROR)
    console_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    root.addHandler(console_handler)

    logging.getLogger('paramiko').setLevel(logging.WARNING)
    logging.getLogger('fabric').setLevel(logging.WARNING)
    logging.getLogger('invoke').setLevel(logging.WARNING)


def _host_label(server_creds):
    # Use friendly name if available, otherwise use host IP
    base = server_creds.friendly_name if server_creds.friendly_name else server_creds.host
    label = base.replace(":", "_").replace("/", "_").replace(" ", "_")
    if getattr(server_creds, 'port', 22) != 22:
        label = f"{label}_{server_creds.port}"
    return label


class _ThreadFilter(logging.Filter):
    def __init__(self, thread_id):
        super().__init__()
        self.thread_id = thread_id

    def filter(self, record):
        return record.thread == self.thread_id


@contextmanager
def _host_log_handler(task_name, host_label, timestamp=None):
    if timestamp is None:
        from datetime import datetime
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
    log_dir = Path("logs") / task_name / host_label
    log_dir.mkdir(parents=True, exist_ok=True)
    log_path = log_dir / f"{timestamp}.log"

    handler = logging.FileHandler(log_path)
    handler.setLevel(logging.DEBUG)
    handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    handler.addFilter(_ThreadFilter(threading.get_ident()))

    root = logging.getLogger()
    root.addHandler(handler)
    try:
        yield log_path
    finally:
        root.removeHandler(handler)
        handler.close()
