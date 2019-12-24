from trivy_py import trivy_pb2_twirp as twirp
from trivy_py import trivy_pb2 as trivy

TRIVY_SERVER = "http://localhost:4954"

def detected_os_vulnerability(os_family, os_name, pb_packages):
    request = trivy.OSDetectRequest(
        os_family=os_family, os_name=os_name, packages=pb_packages
    )
    return twirp.OSDetectorClient(TRIVY_SERVER).detect(request)

def detected_lib_vulnerability(file_path, pb_libraries):
    request = trivy.LibDetectRequest(file_path=file_path, libraries=pb_libraries)
    return twirp.LibDetectorClient(TRIVY_SERVER).detect(request)

if __name__ == "__main__":
    pb_libraries = [
          trivy.Library(
              name="nokogiri",
              version="1.10.3",
          )
    ]
    file_path = "Gemfile.lock"
    print(detected_lib_vulnerability(file_path, pb_libraries))

    os_family = "alpine"
    os_name = "3.9"
    pb_packages = [
          trivy.Package(
              name="openldap",
              version="2.4.47",
              epoch=0,
              arch="",
              release="",
          )
    ]
    print(detected_os_vulnerability(os_family, os_name, pb_packages))
