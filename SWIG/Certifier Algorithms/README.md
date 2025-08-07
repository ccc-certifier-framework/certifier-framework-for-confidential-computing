> `key_message` (in `certifier_algorithms.h`) is a protobuf class. To wrap it in SWIG, I have created a SWIG-friendly wrapper class.
> The wrapper class internally uses `key_message` and exposes clean `std::string' methods for"
> - loading a key
> - exporting a key
> - signing/verification
