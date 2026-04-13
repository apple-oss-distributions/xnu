#!/usr/bin/env zsh -e -u


# This is a script that creates a disk image with slow IO (a fake, artificial disk that lives on ram resources), 
# and then runs the vm stress test with one single configuration on objects that are backed by files in that disk. 
# In the end it's going to eject the newly created volume.

eject_volumes() {
  diskutil list | awk '/disk image/{print $1}' | tail -r | xargs -L1 diskutil eject
}

trap eject_volumes EXIT

# Default values for the flags
SIZE_MB=2048
HELP=false
RAMDISK_MP="/Volumes/apfs-dmg"
SLOW_DMG="slow-dmg.dmg"
TYPE="ssd"
IOQUEUE_DEPTH=1
ACCESS_TIME=$((1 << 18))  		# in microseconds
READ_THROUGHPUT=1000	    # in MB/s
WRITE_THROUGHPUT=1000		# in MB/s
MAX_READ_CNT=$((1 << 10))   # max bytes per read (1Kb)
MAX_WRITE_CNT=$((1 << 10))  # max bytes per write (1Kb)
SEG_READ_CNT=$((1 << 10))  
SEG_WRITE_CNT=$((1 << 10)) 


show_help() {
    echo "Usage: sudo $0 [options]"
    echo
    echo "Running this script will create a ramdisk with a disk image configured to run slower than usual, "
    echo "and then run the vm_stress test on a file that comes from this disk image."
	echo
    echo "Options:"
    echo "  -h, --help        Show this help message"
    echo "  -s, --speed       Set paging speed (slower, slowerer, slowest)"
    echo
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)
            HELP=true
            shift
            ;;
        
        -s|--speed|-S)
            if [[ -z "$2" ]]; then
                echo "Error: --speed requires a value (slower, slowerer, slowest)."
                exit 1
            fi
            case "$2" in
                slower)
					((ACCESS_TIME = ACCESS_TIME * 2))
                    shift 2
                    ;;
                slowerer)
					((ACCESS_TIME = ACCESS_TIME * 3))
                    shift 2
                    ;;
                slowest)
					((ACCESS_TIME = ACCESS_TIME * 4))
                    shift 2
                    ;;
                *)
                    echo "Error: Invalid speed option '$2'. Valid options are: slow, slower, slowest."
                    exit 1
                    ;;
            esac
            ;;
        
        # Invalid option
        *)
            echo "Error: Invalid option '$1'. Use --help for usage."
            exit 1
            ;;
    esac
done

# Show help if requested
if $HELP; then
    show_help
    exit 0
fi

echo "Selected speed: access = $ACCESS_TIME"


diskutil list | awk '/disk image/{print $1}' | tail -r | xargs -L1 diskutil eject								# start fresh with no extra volumes
sysctl debug.didevice_queue_depth=1
ramdisk_device=$(diskutil image attach "ram://${SIZE_MB}m" | awk '{print $1}')									# attach ("create, make visible and mount") disk image ("virtual disk") on RAM (just a disk with no file system)
diskutil eraseDisk apfs apfs-dmg "$ramdisk_device"																# put a file system on it

diskutil image create blank "$RAMDISK_MP/$SLOW_DMG" -size "$((SIZE_MB / 2))m" -volumeName apfs-slow				# create another (seemingly regular) disk image ("virtual disk") in the new ramdisk
slow_di_device=$(diskutil image attach "$RAMDISK_MP/$SLOW_DMG" | awk 'END{print $1}')							# attach it ("make it visible and mount")

purge																											# delete all caches

# configure IO to be slow on the newly created inner volume, and then apply (start):
dmc configure "$RAMDISK_MP" "$TYPE" "$ACCESS_TIME" "$READ_THROUGHPUT" "$WRITE_THROUGHPUT" "$IOQUEUE_DEPTH" "$MAX_READ_CNT" "$MAX_WRITE_CNT" "$SEG_READ_CNT" "$SEG_WRITE_CNT"				
dmc start "$RAMDISK_MP/"

# Now that the ramdisk exists, find and execute the test:
SCRIPT_DIR=$(dirname "$(realpath "$0")")
TEST_EXEC_DIR=$(find "$SCRIPT_DIR/../" -iname "vm_stress" -maxdepth 5 -print -quit)
"$TEST_EXEC_DIR" config -- topo 6 50 5 5 1 1 -s
"$TEST_EXEC_DIR" config -- over 6 50 5 5 1 1 -s
"$TEST_EXEC_DIR" config -- part 6 50 5 5 1 1 -s
"$TEST_EXEC_DIR" config -- one_to_many 6 50 5 5 1 1 -s
"$TEST_EXEC_DIR" config -- one_to_many 6 50 5 5 0 0 -s
dmc stop "$RAMDISK_MP/"