# Battlefield 2 - An EA game.
# Pattern attributes: ok notsofast
# Protocol groups: game proprietary
# Wiki: http://www.protocolinfo.org/wiki/Battlefield_2
#
# This pattern is unconfirmed.


battlefield2
# gameplay|account-login|server browsing/information
# See http://protocolinfo.org/wiki/Battlefield_2
# Can we put a ^ on the last branch?  If so, nosofast --> veryfast
^(\x11\x20\x01\xa0\x98\x11|\xfe\xfd.?.?.?.?.?.?(\x14\x01\x06|\xff\xff\xff))|[]\x01].?battlefield2
