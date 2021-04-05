# IATDelete

An example project that removes the IAT at runtime. This is mainly used as an anti dumping technique, but can be used to mess with some EDR or AV tools that delay inject and attempt
to resolve imports via the IAT (GetProcAddress()). Also breaks any dynamic injections that would attempt to do IAT based API hooking.
