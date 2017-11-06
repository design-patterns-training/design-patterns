import os
import abc


class ScanHandlerBase(object):
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def handle_sensitive(self, file_path, sensitive_pattern, max_size):
        pass

    @abc.abstractmethod
    def handle_non_sensitive(self, file_path, sensitive_pattern, max_size):
        pass

    @abc.abstractmethod
    def handle_skipped(self, file_path, sensitive_pattern, max_size):
        pass

    def __enter__(self):
        pass

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass


class CompositeScanHandler(ScanHandlerBase):
    def __init__(self):
        super(CompositeScanHandler, self).__init__()
        self._handlers = []

    def add_handler(self, handler):
        """
        :type handler: ScanHandlerBase
        :rtype: CompositeFileHandler
        """
        self._handlers.append(handler)
        return self

    def handle_sensitive(self, file_path, sensitive_pattern, max_size):
        for handler in self._handlers:
            handler.handle_sensitive(file_path, sensitive_pattern, max_size)

    def handle_non_sensitive(self, file_path, sensitive_pattern, max_size):
        for handler in self._handlers:
            handler.handle_non_sensitive(file_path, sensitive_pattern, max_size)

    def handle_skipped(self, file_path, sensitive_pattern, max_size):
        for handler in self._handlers:
            handler.handle_skipped(file_path, sensitive_pattern, max_size)

    def __enter__(self):
        for handler in self._handlers:
            handler.__enter__()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        for handler in self._handlers:
            handler.__exit__(exc_type, exc_val, exc_tb)


class LogScanHandler(ScanHandlerBase):
    def handle_sensitive(self, file_path, sensitive_pattern, max_size):
        print "file '{}' contains a sensitive content '{}'".format(file_path, sensitive_pattern)

    def handle_non_sensitive(self, file_path, sensitive_pattern, max_size):
        print "file '{}' does not contain a sensitive content '{}'".format(file_path, sensitive_pattern)

    def handle_skipped(self, file_path, sensitive_pattern, max_size):
        print "file '{}' exceeds the size threshold {}".format(file_path, max_size)


class LogStatsScanHandler(ScanHandlerBase):
    def handle_sensitive(self, file_path, sensitive_pattern, max_size):
        stats = os.stat(file_path)
        print "sensitive file '{}' is owned by '{}' and was modified at {}".format(file_path, stats.st_uid, stats.st_mtime)

    def handle_non_sensitive(self, file_path, sensitive_pattern, max_size):
        pass

    def handle_skipped(self, file_path, sensitive_pattern, max_size):
        pass


class OutputToFileScanHandler(ScanHandlerBase):
    def __init__(self, output_file_path):
        super(OutputToFileScanHandler, self).__init__()
        self._output_file_path = output_file_path

    def __enter__(self):
        self._output_file = open(self._output_file_path, "w")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self._output_file.close()
            
    def handle_sensitive(self, file_path, sensitive_pattern, max_size):
        self.report("file '{}' contains a sensitive content '{}'".format(file_path, sensitive_pattern))

    def handle_non_sensitive(self, file_path, sensitive_pattern, max_size):
        self.report("file '{}' does not contain a sensitive content '{}'".format(file_path, sensitive_pattern))

    def handle_skipped(self, file_path, sensitive_pattern, max_size):
        self.report("file '{}' exceeds the size threshold {}".format(file_path, max_size))

    def report(self, msg):
        self._output_file.write(msg + "\n")
