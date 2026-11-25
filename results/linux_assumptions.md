# Linux assumption list
- grep found no /tmp, os.fork, resource, chmod or bash calls
- os.path.abspath at line 1053 should become pathlib
- open(a.json, "w") at line 1204 has no encoding. Add encoding utf-8
- No multiprocessing code yet. Future harness code must sit under if __name__ == "__main__"
- Memory uses tracemalloc, not the Linux resource module. Add psutil peak_wset for Windows
