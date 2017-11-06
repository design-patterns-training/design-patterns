import os
import csv
import zipfile

from scan_handler_builders import VerboseScanHandlerBuilder, BriefScanHandlerBuilder

DEBUG = True
VERBOSE = False


class Scanner(object):

    @classmethod
    def _iterate_file_content(cls, file_path):
        if zipfile.is_zipfile(file_path):
            with zipfile.ZipFile(file_path) as zip_file:
                for zip_info in zip_file.infolist():
                    inner_file = zip_file.open(zip_info)
                    for line in inner_file.readlines():
                        yield line
        else:
            with open(file_path, 'r') as file_to_scan:
                header = file_to_scan.read(1024)
                file_to_scan.seek(0)

                try:
                    dialect = csv.Sniffer().sniff(header)
                    for row in csv.reader(file_to_scan, dialect):
                        for cell in row:
                            yield cell
                except csv.Error:
                    file_to_scan.seek(0)
                    for line in file_to_scan.readlines():
                        yield line

    @classmethod
    def scan(cls, dir_to_scan, sensitive_pattern, max_size, scan_handler):
        """
        :type scan_handler: scan_handlers.ScanHandlerBase
        """
        for dir_path, _, file_names in os.walk(dir_to_scan):
            for file_name in file_names:
                file_path = os.path.normpath(os.path.join(dir_path, file_name))
                if os.path.getsize(file_path) > max_size:
                    scan_handler.handle_skipped(file_path, sensitive_pattern, max_size)
                    continue

                if any((sensitive_pattern in chunk for chunk in cls._iterate_file_content(file_path))):
                    scan_handler.handle_sensitive(file_path, sensitive_pattern, max_size)
                    continue
                scan_handler.handle_non_sensitive(file_path, sensitive_pattern, max_size)


def test_scanner(scan_handler_builder):
    """
    :type scan_handler_builder: scan_handler_builders.ScanHandlerBuilderBase
    """
    samples_dir = os.path.join(os.path.dirname(__file__), "samples")
    output_file = os.path.join(os.path.dirname(__file__), "output", "result.txt")

    scan_handler_builder.add_output_file_handler(output_file)
    if DEBUG:
        scan_handler_builder.add_stdout_handler()

    with scan_handler_builder.build() as scan_handler:
        Scanner.scan(samples_dir, "Sensitive", 1337, scan_handler)


if __name__ == "__main__":
    test_scanner(VerboseScanHandlerBuilder() if VERBOSE else BriefScanHandlerBuilder())
