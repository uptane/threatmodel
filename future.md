# Things that need to be addressed in future versions
### Director repository verification
Currently, the director repository doesn't really verify what it receives from the image repository. It trusts the image repo, which shouldn't be the case.
Zero-trust must be built into the design, as this leaves the door open for attacks like rollback, mix-and-match, etc. to take place from the source itself (director)
Some sort of "verification" akin to the one done on the vehicle must be done on the director repository to ensure that it is safe from attempts like these. 

### Second thing 
I don't remember what it was but I'll add this in after discussing with Phil.

### Third thing
Remote attestations

### Disambiguate report
Change the usage of the word "report" where it is a verb to "flag" or "record" or "log"
