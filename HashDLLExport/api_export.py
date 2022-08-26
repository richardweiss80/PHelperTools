import os
import pefile

path_system32 = os.path.join(os.environ['windir'], 'System32')
dll_names = ['kernel32.dll', 'user32.dll', 'advapi32.dll', 'wininet.dll', 'ws2_32.dll', 'shell32.dll', 'urlmon.dll',
             'ole32.dll']


def export_parse(file, api_names) -> bool:
    try:
        pe = pefile.PE(os.path.join(path_system32, file))
        try:
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    api_names.append(exp.name.decode('utf-8'))
        except AttributeError:
            print(f'File {file} has not Attribute DIRECTORY_ENTRY_EXPORT')
            return False
        return True
    except OSError:
        print(f'File {file} not found')
        return False


def main():
    api_names = []
    module_names = []

    for dll in dll_names:
        if export_parse(dll, api_names):
            module_names.append(dll)

    output = f"module_names = {module_names}{os.linesep}api_names = {api_names}"

    if args.output:
        with open(args.output, "w") as file:
            file.write(output)
    else:
        print(output)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Export DLL Exported Functions')
    parser.add_argument('-o', '--output', help='Results are written to this file')

    args = parser.parse_args()
    main()
