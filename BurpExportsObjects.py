from burp import IBurpExtender, IRequestInfo, IContextMenuFactory
from java.io import PrintWriter
from javax.swing import JMenu, JMenuItem

# File I/O
from java.io import File, FileOutputStream

# Path
from java.net import URI


class BurpExtender(IBurpExtender, IRequestInfo, IContextMenuFactory):
    def registerExtenderCallbacks(self, callbacks):
        self._actionName = "Export Objects"
        self._helers = callbacks.getHelpers()
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Export Objects")
        callbacks.registerContextMenuFactory(self)

        # obtain our output and error streams
        self._stderr = PrintWriter(callbacks.getStderr(), True)
        self._stdout = PrintWriter(callbacks.getStdout(), True)

        # write a message to the Burp alerts tab
        callbacks.issueAlert("Installed Export Objects.")

    def createMenuItems(self, invocation):
        menu = JMenu(self._actionName)
        menu.add(
            JMenuItem(
                "Export",
                None,
                actionPerformed=lambda x, inv=invocation: self.Action(inv),
            )
        )
        return [menu]

    def Action(self, invocation):
        try:
            http_traffic = invocation.getSelectedMessages()
            traffic_length = len(http_traffic)
            counter = 0

            self._stdout.println(">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")

            while len(http_traffic) > 0:
                counter += 1
                target_traffic = http_traffic.pop()
                analyzedRequest = self._helpers.analyzeRequest(
                    target_traffic
                )
                analyzedResponse = self._helpers.analyzeResponse(
                    target_traffic.getResponse()
                )

                status_code = analyzedResponse.getStatusCode()
                mime_type = analyzedResponse.getStatedMimeType()
                url = analyzedRequest.getUrl()
                body_offset = analyzedResponse.getBodyOffset()

                # resolve filename from url.
                file_name = self.extract_filename(url)

                # check extention.
                if not self.has_extention(file_name):
                    ex = self.guess_extention(mime_type,
                                              target_traffic.getResponse())
                    file_name = file_name + "." + ex

                output_dir = "/tmp"
                file_path = output_dir + "/" + file_name
                self._stdout.printf("[%d/%d]\n", counter, traffic_length)
                self._stdout.printf("url: %s\n", url)
                self._stdout.printf("status_code: %d\n", status_code)
                self._stdout.printf("mime_type: %s\n", mime_type)
                self._stdout.printf("body_offset: %d\n", body_offset)
                self._stdout.printf("save as \"%s\".\n\n", file_path)

                # extract object
                self.extract_obj(file_path,
                                 target_traffic.getResponse(),
                                 body_offset)

            self._stdout.println("<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<")

        except Exception as e:
            self._stderr.println("[!] In Action.")
            self._stderr.println(e)

    def extract_filename(self, url):
        uri = url.toURI()
        path = uri.getPath().encode('utf-8')
        file_name = path.split("/")[-1]
        return file_name

    def has_extention(self, file_name):
        return len(file_name.split(".")) > 1

    def guess_extention(self, mime, res):
        if mime == "JPEG":
            return "jpg"
        elif mime == "GIF":
            return "gif"
        elif mime == "PNG":
            return "png"
        else:
            return ""

    def extract_obj(self, file_path, res, offset):
        try:
            f = File(file_path)

            # check same name file.
            counter = 0
            while True:

                # The same file name is not exists.
                if not f.exists():
                    break

                # Count up the file name.
                counter += 1
                stem = "".join(file_path.split(".")[:-1])
                ex = file_path.split(".")[-1]

                _file_path = "{}({}).{}".format(stem, counter, ex)
                f = File(_file_path)

            fos = FileOutputStream(f)

            fos.write(res[offset:])
            fos.close()

        except Exception as e:
            self._stderr.println("[!] In extract_obj.")
            self._stderr.println(e)
