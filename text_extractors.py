import abc
import csv
import zipfile


class Singleton(abc.ABCMeta):
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]


class TextExtractorBase(object):
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def handle(self, file_path):
        pass


class ChainedTextExtractorBase(TextExtractorBase):
    __metaclass__ = abc.ABCMeta

    def __init__(self, successor=None):
        super(ChainedTextExtractorBase, self).__init__()
        self._successor = successor

    # noinspection PyUnusedLocal
    @abc.abstractmethod
    def _can_handle(self, file_path):
        return True

    @abc.abstractmethod
    def _iterate(self, file_path):
        pass

    def handle(self, file_path):
        if self._can_handle(file_path):
            return self._iterate(file_path)

        assert self._successor is not None
        return self._successor.handle(file_path)


class PlainTextExtractor(ChainedTextExtractorBase):
    __metaclass__ = Singleton

    def _can_handle(self, file_path):
        return True

    def _iterate(self, file_path):
        with open(file_path, 'r') as file_to_scan:
            for line in file_to_scan.readlines():
                yield line


class CsvTextExtractor(ChainedTextExtractorBase):
    __metaclass__ = Singleton

    def _can_handle(self, file_path):
        with open(file_path, 'r') as file_to_scan:
            header = file_to_scan.read(1024)
            try:
                csv.Sniffer().sniff(header)
                return True
            except csv.Error:
                return False

    def _iterate(self, file_path):
        with open(file_path, 'r') as file_to_scan:
            header = file_to_scan.read(1024)
            dialect = csv.Sniffer().sniff(header)
            for row in csv.reader(file_to_scan, dialect):
                for cell in row:
                    yield cell


class ZipTextExtractor(ChainedTextExtractorBase):
    __metaclass__ = Singleton

    def _can_handle(self, file_path):
        return zipfile.is_zipfile(file_path)

    def _iterate(self, file_path):
        with zipfile.ZipFile(file_path) as zip_file:
            for zip_info in zip_file.infolist():
                inner_file = zip_file.open(zip_info)
                for line in inner_file.readlines():
                    yield line


class TextExtractor(TextExtractorBase):
    __metaclass__ = Singleton

    def __init__(self):
        super(TextExtractor, self).__init__()
        self._handler = ZipTextExtractor(CsvTextExtractor(PlainTextExtractor()))

    def handle(self, file_path):
        return self._handler.handle(file_path)
