class IntelMonitorError(Exception):
    """所有监测富化异常的基类"""
    pass


class CollectorError(IntelMonitorError):
    """采集器异常"""
    pass


class EnrichmentError(IntelMonitorError):
    """富化异常"""
    pass


class StorageError(IntelMonitorError):
    """存储异常"""
    pass


class NotFoundError(IntelMonitorError):
    """记录不存在"""
    pass