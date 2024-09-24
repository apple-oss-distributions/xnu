""" Python I/O subsystem backed by LLDB. """

import io
import lldb


class SBProcessRawIO(io.RawIOBase):
    """ RAW I/O implementation backed by a process memory. """

    def __init__(self, sbprocess, address, size):
        """ Create new SBProcess I/O.

            sbproces: SBProcess instance to read data from.
            address: Starting memory address in process' VA.
            size: Size of the memory range.
        """
        super().__init__()

        self._sbprocess = sbprocess
        self._start = address
        self._offset = 0
        self._end = address + size

    # Base I/O methods

    def readable(self):
        return True

    def writable(self):
        # This is a lie that allows using BufferedRandom on top of this I/O.
        return True

    def seekable(self):
        return True

    # Raw I/O methods

    def tell(self):
        return self._offset

    def seek(self, offset, whence=0):
        seekto = offset
        if whence == 0:
            seekto += 0
        elif whence == 1:
            seekto += self.tell()
        elif whence == 2:
            seekto += self._end - self._start
        else:
            raise IOError("Invalid whence argument to seek: %r" % (whence,))

        self._offset = seekto
        return seekto

    def read(self, size=-1):
        if size < 0:
            return self.readall()

        # Do not read past the end of the data range.
        read_size = min(size, self._end - (self._start + self._offset))

        err = lldb.SBError()
        data = self._sbprocess.ReadMemory(self._start + self._offset, read_size, err)

        # EOF on failure
        if not err.Success():
            return bytes()

        self._offset += len(data)
        return bytes(data)

    def readall(self):
        err = lldb.SBError()
        data = self._sbprocess.ReadMemory(self._start, self._end - self._start, err)

        if not err.Success():
            return bytes()

        return bytes(data)

    def readinto(self, bytes):
        """ Reads data into existing object. """
        data = self.read(len(bytes))
        if data:
            bytes[:len(data)] = data
        return len(data)

    def readlines(self, hint=-1):
        raise NotImplementedError("Can't read lines yet.")

    def write(self, bytes):
        raise NotImplementedError("Can't write through LLDB yet.")
