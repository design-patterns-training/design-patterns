import os


DEBUG = True


class Scanner(object):
    @classmethod
    def report(cls, output_file, msg):
        if DEBUG:
            print msg
        output_file.write(msg + "\n")

    @classmethod
    def scan(cls, dir_to_scan, sensitive_pattern, max_size, output_file):
        for dir_path, _, file_names in os.walk(dir_to_scan):
            for file_name in file_names:
                file_path = os.path.normpath(os.path.join(dir_path, file_name))
                if os.path.getsize(file_path) > max_size:
                    cls.report(output_file, "file '{}' exceeds the size threshold {}".format(file_path, max_size))
                    continue

                with open(file_path, "r") as file_to_scan:
                    if any((sensitive_pattern in line for line in file_to_scan.readlines())):
                        cls.report(output_file, "file '{}' contains a sensitive content '{}'".format(file_path, sensitive_pattern))
                        continue
                cls.report(output_file, "file '{}' does not contain a sensitive content '{}'".format(file_path, sensitive_pattern))


def test_scanner():
    samples_dir = os.path.join(os.path.dirname(__file__), "samples")
    output_file = os.path.join(os.path.dirname(__file__), "output", "result.txt")
    with (open(output_file, "w")) as output_file:
        Scanner.scan(samples_dir, "Sensitive", 1337, output_file)


if __name__ == "__main__":
    test_scanner()
