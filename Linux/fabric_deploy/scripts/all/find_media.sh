find_media() {
    chkdir="/home/"
    dmpfile="$HOME/media_files.txt"

    header "\nChecking for media files in ${chkdir}"
    : > "$dmpfile"

    # Expanded formats (space-separated for POSIX sh)
    extensions='
txt log md rtf pdf doc docx odt xls xlsx ods ppt pptx odp csv json xml yaml yml
jpg jpeg png gif webp bmp tiff tif heic heif svg ico raw cr2 nef arw dng
mp3 m4a m4b aac flac ogg opus wav wma aiff aif amr mid midi
mp4 m4v mov mkv avi webm wmv flv mpg mpeg m2v 3gp ts mts m2ts
zip tar gz tgz bz2 tbz2 xz txz 7z rar zst
iso img dmg qcow2 vmdk
'

    for ext in $extensions
    do
        find "$chkdir" -type f -name "*.$ext" 2>/dev/null | tee -a "$dmpfile" >/dev/null
        count=$(find "$chkdir" -type f -name "*.$ext" 2>/dev/null | wc -l | tr -d ' ')
        echo "Found $count"
        success "Checking $ext files."
    done

    printf "\n"
    notify "Saving media file paths to ${dmpfile}"
}
