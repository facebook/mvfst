---
sidebar_position: 1
---

# Blocking vs non-Blocking I/O

Mvfst is, at its core, an [IO
library](https://en.wikipedia.org/wiki/Input/output). It allows an
application to setup a QUIC connection to a peer and read/write data on that
connection using the QUIC semantics of streams and datagrams. When doing I/O
to a device/network/whatever there is one main design choice which needs to
be made: should the reads and writes be "blocking" or not?


## Blocking I/O
Blocking I/O, is perhaps the easier model to understand. Suppose, for
example, we have a QUIC stream and we want to write some data to it. That may
look like the following in pseudo code:
```
quicStream = createBidirectionalStream()
message = "hello my friend"
quicStream.write(message) // Blocks until the message is fully written to the network.
print("I have successfully written the message!")
```
In a blocking I/O model the call to write will not return (i.e. "block")
until it has written "hello my friend" into QUIC packets and into the
network. The case of reading in a blocking fashion is similar:
```
message = quicStream.readAll() // Blocks until the entire stream is available.
print("here is the message: " + message)
```
The call to `read` will block until it has 15 bytes to return. This is all
pretty straightforward, and indeed blocking I/O makes it very easy to write
traditional programs; I/O functions are really no different from any other
function besides the fact that the time it takes to return isn't solely a
function of CPU time.

There are, however, significant practical disadvantages to using blocking
I/O. Consider for example a web server which handles multiple concurrent
connections from clients. Using only a single thread of execution this server
would only be able to serve one client at a time, as every I/O call will
block execution until its completion. One way to get around this is to
instead have a [thread](https://en.wikipedia.org/wiki/Thread_(computing)) per
connection. This enables the server to service multiple clients without any
connection delaying the servicing of any other connection. However, in order
to achieve this concurrency the server needs many threads. It is not unusual
for modern web servers to have to service tens to hundreds of thousands of
connections concurrently, leading to the so-called
[C10k](https://en.wikipedia.org/wiki/C10k_problem) problem. Threads are not
free, and their management, whether done by the operating system or in the
userspace runtime via [green
threads](https://en.wikipedia.org/wiki/Green_threads), cannot feasibly scale
to support this model.

An alternative approach is to use non-blocking I/O. The basic idea with
non-blocking I/O is obviously to have the I/O functions not block until their
completion, and return pretty much immediately. This sounds simple but poses
a further problem -- how is the program supposed to act on the results of the
I/O operation? The answer is to use some form of
["continuation"](https://en.wikipedia.org/wiki/Continuation) -- i.e. to
structure the code such that on the completion of the I/O the program can
consume the result and do something with it. Let's consider our write example
again, but now the call to `write` does not block waiting for the I/O to
complete:

```
quicStream = createBidirectionalStream()
message = "hello my friend"
quicStream.write(message) // Returns after copying message into a buffer to be sent later.
print("I have successfully written the message!")
```

Our statement in the print is no longer true, since we don't know if the
message has been written yet. To ensure it remains true we can introduce a form
of continuation such that when the I/O does complete we will be able to react
by printing the message. We do this by passing a function to the `write` API:

```
quicStream = createBidirectionalStream()
message = "hello my friend"
myCallback = (){print("I have successfully written the message!")}
quicStream.write(message, myCallback) // Returns after copying message into a buffer to be sent later.
```

As before `write` still returns immediately, but now we have a way to execute
some code at the same point as the blocking I/O example, when the message is
written to the network. This code can now be said to be using a form of
"asynchronous continuation" in the form of a callback function (i.e., the
function is "called back" when the operation completes).

If we consider the `read` case we see the same problem. We want to only print
the message once we've actually received it, without blocking on a function
call. To achieve this we would have a similar callback:


```
myCallback = (quicStream){print("here is the message: " + quicStream.readAll())}
quicStream.setReadCallback(myCallback)
```

Now we are telling the QUIC implementation to call `myCallback` when it has
read data from the stream. The callback is provided the stream which has had
all of its data read, and the readAll function simply copies it out of the
connection.

Callbacks are the most primitive form of achieving continuation and they can
be difficult to reason about. C++ (and many other languages) now has support
for a different semantic,
[coroutines](https://en.wikipedia.org/wiki/Coroutine), which allows for a
more structured way to program with asynchronous continuations. In general
mvfst only offers completely asynchronous APIs that use callbacks for
continuation.
