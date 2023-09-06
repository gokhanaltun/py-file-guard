import os
from data import Data

def file_read_bytes(path: str):
    try:
        if os.path.exists(path):
            with open(path, "rb") as file:
                return Data(data=file.read())
        else:
            return Data(error="file not found")
    except Exception as e:
        return Data(error=e)
def file_write_bytes(file_data: bytes, path: str):
    try:
        if os.path.exists(path):
            with open(path, "wb") as file:
                file.write(file_data)
        else:
            return Data(error="file not found")
    except Exception as e:
        return Data(error=e)