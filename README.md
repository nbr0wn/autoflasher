I needed something to bulk flash an image to a bunch of SD cards, so I whipped this thing up.  It waits for devices to be connected and then writes the given image to them if they meet the specified criteria.

It has a watch mode which will detect udev changes and print them, but do nothing else.

It has a flash mode which will detect udev changes and attempt to write the given image to them IF:

- The device was not present when the program started - only new devices will be considered
- The device type matches (ata, usb, sd etc.)

