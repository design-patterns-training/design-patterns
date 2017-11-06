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


class OutputToFileScanHandler(ScanHandlerBase):
    def __init__(self, output_file_path, is_debug=False):
        super(OutputToFileScanHandler, self).__init__()
        self._output_file_path = output_file_path
        self._is_debug = is_debug

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
        if self._is_debug:
            print msg
        self._output_file.write(msg + "\n")
