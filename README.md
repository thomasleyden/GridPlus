# GridPlus Code Exam (C)
> Estimated time: ~4hrs

## About this exam
This code exam will make use of an existing TLV (tag-length-value) codec
library. The exam questions will involve finding bugs and adding improvements
to the library. If you are unfamiliar with TLV encoding, the following
resources may be helpful:

* Wikipedia has a good high level overview 
[[link](https://en.wikipedia.org/wiki/Type-length-value)]
* Section 8 of the TLV spec is particularly informative 
[[link](https://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf)]

The exam questions should be answered as git commits. When the exam is
complete, you may zip the repository and submit it to the reviewer. The
reviewer may go over each commit with you in a follow-up interview.

## About this library
The library has been modified, for the purpose of this exam, to include some
intentional bugs (and perhaps some unintentional ones :) ). The source code can
be found in `tlv.h` & `tlv.c`. Test code is available in the `test/` directory.

To run the tests, `cd` into the test directory and execute the build script. The
test binary will be built at `test/build/test`. Execute this binary to run the
tests:
```
cd test
./build.sh
./build/test
```
The tests assume a few basic dependencies to build a C program (`gcc`, `cmake`,
`make`). Most modern systems include these dependencies by default, but you may
need to install them manually.

# Exam Questions
## Question 1
Each question should be answered as a git commit. As a pre-requisite, please
set up a git repository for this folder, with the current contents as an
"Initial commit". Create a new branch called `solutions`. All subsequent
questions should be answered in subsequent commits on this branch.

## Question 2
This library includes several bugs. Please find the bugs and resolve them.

## Question 3
Please add a new function to this library's API. The function should search a
TLV encoded byte array for a specified "tag", and return the byte offset of the
tag within the array.

## Question 4
Please add a test for your new API in `test/test.c`

# Submitting
Once you have finished this exam, please either zip the repo up and return it over email to alex@gridplus.io or publish it on GitHub and email a link instead.

We expect to have your answers 30 minutes before the start of your review meeting, at the latest. Most emphasis is placed on the work itself, but we do take note of how long it takes you, so we recommend submitting it when you are satisfied with its completion.
