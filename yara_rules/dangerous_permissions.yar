rule Dangerous_Permissions
{
    strings:
        $send_sms = "android.permission.SEND_SMS"
        $record_audio = "android.permission.RECORD_AUDIO"
        $read_contacts = "android.permission.READ_CONTACTS"
        $camera_access = "android.permission.CAMERA"
        $write_storage = "android.permission.WRITE_EXTERNAL_STORAGE"
        $read_sms = "android.permission.READ_SMS"
        $call_phone = "android.permission.CALL_PHONE"
    condition:
        any of them
}
