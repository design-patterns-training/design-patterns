import abc

from scan_handlers import CompositeScanHandler, LogScanHandler, LogStatsScanHandler, OutputToTxtScanHandler, OutputToCsvScanHandler


class ScanHandlerBuilderBase(object):
    __metaclass__ = abc.ABCMeta

    def __init__(self):
        self._handler = CompositeScanHandler()

    @abc.abstractmethod
    def add_stdout_handler(self):
        pass

    @abc.abstractmethod
    def add_output_file_handler(self, output_file_path):
        pass

    @abc.abstractmethod
    def build(self):
        pass


class VerboseScanHandlerBuilder(ScanHandlerBuilderBase):

    def add_stdout_handler(self):
        self._handler.add_handler(LogScanHandler())
        self._handler.add_handler(LogStatsScanHandler())

    def add_output_file_handler(self, output_file_path):
        self._handler.add_handler(OutputToTxtScanHandler(output_file_path))

    def build(self):
        return self._handler


class BriefScanHandlerBuilder(ScanHandlerBuilderBase):
    def add_stdout_handler(self):
        self._handler.add_handler(LogScanHandler())

    def add_output_file_handler(self, output_file_path):
        self._handler.add_handler(OutputToCsvScanHandler(output_file_path))

    def build(self):
        return self._handler
