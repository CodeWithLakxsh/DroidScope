package com.droidscope.secure;

import android.app.Service;
import android.content.Intent;
import android.os.IBinder;
import java.io.File;
import java.io.FileOutputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/** Exported, but guarded by a signature-level permission in the manifest. */
public class SyncService extends Service {

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    /** Each entry's resolved path is confirmed to stay inside the destination. */
    public void unpack(ZipInputStream zip, File destination) throws Exception {
        String root = destination.getCanonicalPath();
        ZipEntry entry;
        while ((entry = zip.getNextEntry()) != null) {
            File target = new File(destination, entry.getName());
            if (!target.getCanonicalPath().startsWith(root + File.separator)) {
                throw new SecurityException("archive entry escapes the destination directory");
            }
            try (FileOutputStream out = new FileOutputStream(target)) {
                byte[] buffer = new byte[4096];
                int read;
                while ((read = zip.read(buffer)) != -1) {
                    out.write(buffer, 0, read);
                }
            }
        }
    }
}
