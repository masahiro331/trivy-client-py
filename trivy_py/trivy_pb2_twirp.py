# Code generated by protoc-gen-twirp_python v5.9.0, DO NOT EDIT.
# source: trivy.proto

try:
    import httplib
    from urllib2 import Request, HTTPError, urlopen
except ImportError:
    import http.client as httplib
    from urllib.request import Request, urlopen
    from urllib.error import HTTPError
import json
import sys

from google.protobuf import symbol_database as _symbol_database

_sym_db = _symbol_database.Default()


class TwirpException(httplib.HTTPException):
    def __init__(self, code, message, meta):
        self.code = code
        self.message = message
        self.meta = meta
        super(TwirpException, self).__init__(message)

    @classmethod
    def from_http_err(cls, err):
        try:
            jsonerr = json.load(err)
            code = jsonerr["code"]
            msg = jsonerr["msg"]
            meta = jsonerr.get("meta")
            if meta is None:
                meta = {}
        except:  # noqa: E722
            code = "internal"
            msg = "Error from intermediary with HTTP status code {} {}".format(
                err.code, httplib.responses[err.code]
            )
            meta = {}
        return cls(code, msg, meta)


class OSDetectorClient(object):
    def __init__(self, server_address):
        """Creates a new client for the OSDetector service.
        Args:
            server_address: The address of the server to send requests to, in
                the full protocol://host:port form.
        """
        if sys.version_info[0] > 2:
            self.__target = server_address
        else:
            self.__target = server_address.encode("ascii")
        self.__service_name = "trivy.detector.OSDetector"

    def __make_request(self, body, full_method):
        req = Request(
            url=self.__target + "/twirp" + full_method,
            data=body,
            headers={"Content-Type": "application/protobuf"},
        )
        try:
            resp = urlopen(req)
        except HTTPError as err:
            raise TwirpException.from_http_err(err)

        return resp.read()

    def detect(self, o_s_detect_request):
        serialize = _sym_db.GetSymbol(
            "trivy.detector.OSDetectRequest"
        ).SerializeToString
        deserialize = _sym_db.GetSymbol("trivy.detector.DetectResponse").FromString

        full_method = "/{}/{}".format(self.__service_name, "Detect")
        body = serialize(o_s_detect_request)
        resp_str = self.__make_request(body=body, full_method=full_method)
        return deserialize(resp_str)


class LibDetectorClient(object):
    def __init__(self, server_address):
        """Creates a new client for the LibDetector service.
        Args:
            server_address: The address of the server to send requests to, in
                the full protocol://host:port form.
        """
        if sys.version_info[0] > 2:
            self.__target = server_address
        else:
            self.__target = server_address.encode("ascii")
        self.__service_name = "trivy.detector.LibDetector"

    def __make_request(self, body, full_method):
        req = Request(
            url=self.__target + "/twirp" + full_method,
            data=body,
            headers={"Content-Type": "application/protobuf"},
        )
        try:
            resp = urlopen(req)
        except HTTPError as err:
            raise TwirpException.from_http_err(err)

        return resp.read()

    def detect(self, lib_detect_request):
        serialize = _sym_db.GetSymbol(
            "trivy.detector.LibDetectRequest"
        ).SerializeToString
        deserialize = _sym_db.GetSymbol("trivy.detector.DetectResponse").FromString

        full_method = "/{}/{}".format(self.__service_name, "Detect")
        body = serialize(lib_detect_request)
        resp_str = self.__make_request(body=body, full_method=full_method)
        return deserialize(resp_str)