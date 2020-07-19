# POSH
PowerShell Scripts

This is a PowerShell script for automating much of the initial configuration of Dell's Wyse Thinclient terminals. This script involves medical-enterprise software setup, i.e. MidMark, and applications specific to our needs, e.g. Adobe, so customize the script as needed for your context. 

This script executes in two main sequences: 1) Initial Setup and 2) Domain-Join 

1) Initial Setup:
This sequence takes place in the Wyse Thinclient's factory-default 'Admin' environment (at the time of this writing, Dell's standard password for Wyse thinclients' 'Admin' account is 'DellCCCvdi'). In this environment, the script disables the write-filter and thus requires a reboot. Upon rebooting and logging back into the default Admin environment the script must be run again. In this iteration, the script detects that the write-filter is disabled and proceeds to execute a custom PowerShell script for adding user profiles to Dell's NetXClean exception list, and restarts the NetXClean service. 

Then, the last step in this first sequence is to run a custom script for setting up Admin User accounts in Windows, i.e. adding Administrator accounts and passwords. This sets the stage for the next sequence, which will be run under the newly-created Administrator account.

2) Domain-Join:
This sequence takes place in the newly-created local Administrator account. The first, last, and only step is to join the terminal to the Domain. This requires a reboot. 

Once the computer is joined to the domain, the rest of the script must run in the domain administrator environment. The essential steps of the remaining script are as follows:

- Rename the endpoint

- Configure default user and auto-logon (script calls for reboot to test)
  Note: In my case, target room numbers and the auto-logon password for the terminals are intertwined with each other, thus the references to '$roomNumber'. Customize to your   
  situation as needed.
  
- Various environment configurations, software installations and uninstallations, and so on. 


