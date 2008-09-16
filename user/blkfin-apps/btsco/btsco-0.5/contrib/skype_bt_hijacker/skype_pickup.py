#! /usr/bin/python
# -*- coding: iso-8859-15 -*- 

import dbus, sys, os, string

class Api_obj:
	def __init__(self):
		switchfile = '/tmp/switch_dsp'
		remote_bus = dbus.SystemBus()
		
		system_service_list = remote_bus.get_service('org.freedesktop.DBus').get_object('/org/freedesktop/DBus', 'org.freedesktop.DBus').ListServices()
		skype_api_found = 0

		for service in system_service_list:
			if service=='com.Skype.API':
				skype_api_found = 1
				break

		if not skype_api_found:
			sys.exit('No running API-capable Skype found')

		skype_service = remote_bus.get_service('com.Skype.API')
		self.skype_api_object = skype_service.get_object('/com/Skype','com.Skype.API')

		answer = self.send_message('NAME SkypePickup')
		if answer != 'OK':
			sys.exit('Could not bind to Skype client')

		answer = self.send_message('PROTOCOL 1')
#		if answer != 'PROTOCOL 1':
#			sys.exit('This test program only supports Skype API protocol version 1')

		answer = self.send_message('SEARCH ACTIVECALLS')
		answer = answer[6:]
# if we have multiple calls active, only act on the first one.
		if -1 != string.find(answer,','):
			answer=answer[:string.find(answer,',')]

# if we have no call, disconnect the headset from audio.
		if answer == '':
			if os.access(switchfile,os.F_OK):
				os.unlink(switchfile)
			sys.exit('No call available');

		status = self.send_message('GET CALL '+answer+' STATUS')
		if -1 != string.find(status,"STATUS "):
			status=status[string.find(status,"STATUS ")+7:]
		else:
			status='FIND_ERROR'
# we have a call. If it is ringing, answer it and direct audio to us.
		if status == 'RINGING':
			answer = self.send_message('SET CALL '+answer+' STATUS INPROGRESS')
			if not os.access(switchfile,os.F_OK):
				os.close(os.open(switchfile,os.O_CREAT|os.O_WRONLY,0700))
# if the call is in progress, check if it is directed to the headset.
# if it is, the user wants to hang up.
# if it is not, we pull the call to the headset.
		elif status == 'INPROGRESS':
			if os.access(switchfile,os.F_OK):
				answer = self.send_message('SET CALL '+answer+' STATUS FINISHED')
				os.unlink(switchfile)
			else:
				os.close(os.open(switchfile,os.O_CREAT|os.O_WRONLY,0700))
		else:
# in any other case, bail out.
			sys.exit('Call state '+status+' not handled.');

	# Client -> Skype
	def send_message(self, message):		
		answer = self.skype_api_object.Invoke(message)
		return answer

def main():
	api_object = Api_obj()
	return 0	

if __name__ == "__main__":
	main()
