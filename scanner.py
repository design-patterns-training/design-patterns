import os

from scan_handlers import OutputToFileScanHandler


DEBUG = True


class Scanner(object):

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

                with open(file_path, "r") as file_to_scan:
                    if any((sensitive_pattern in line for line in file_to_scan.readlines())):
                        scan_handler.handle_sensitive(file_path, sensitive_pattern, max_size)
                        continue
                scan_handler.handle_non_sensitive(file_path, sensitive_pattern, max_size)


def test_scanner():
    samples_dir = os.path.join(os.path.dirname(__file__), "samples")
    output_file = os.path.join(os.path.dirname(__file__), "output", "result.txt")
    with OutputToFileScanHandler(output_file, is_debug=DEBUG) as scan_handler:
        Scanner.scan(samples_dir, "Sensitive", 1337, scan_handler)


if __name__ == "__main__":
    test_scanner()
