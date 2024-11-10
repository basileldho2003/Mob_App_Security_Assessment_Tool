rule Dangerous_Permissions
{
    strings:
        $send_sms = /<uses-permission[^>]*android.permission.SEND_SMS[^>]*>/
        $record_audio = /<uses-permission[^>]*android.permission.RECORD_AUDIO[^>]*>/
        $read_contacts = /<uses-permission[^>]*android.permission.READ_CONTACTS[^>]*>/
        $camera_access = /<uses-permission[^>]*android.permission.CAMERA[^>]*>/
        $write_storage = /<uses-permission[^>]*android.permission.WRITE_EXTERNAL_STORAGE[^>]*>/
        $read_sms = /<uses-permission[^>]*android.permission.READ_SMS[^>]*>/
        $call_phone = /<uses-permission[^>]*android.permission.CALL_PHONE[^>]*>/
    condition:
        any of them
}
