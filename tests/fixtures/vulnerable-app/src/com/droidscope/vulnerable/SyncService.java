package com.droidscope.vulnerable;

import android.app.Service;
import android.content.Intent;
import android.os.IBinder;
import java.io.File;
import java.io.FileOutputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/** DroidScope fixture: exported service with unsafe archive handling. */
public class SyncService extends Service {

    @Override
    public IBinder onBind(Intent intent) {
        return null;
    }

    /** DS-CODE-006: archive extracted without validating the entry path. */
    public void unpack(ZipInputStream zip, File destination) throws Exception {
        ZipEntry entry;
        while ((entry = zip.getNextEntry()) != null) {
            File target = new File(destination, entry.getName());
            FileOutputStream out = new FileOutputStream(target);
            byte[] buffer = new byte[4096];
            int read;
            while ((read = zip.read(buffer)) != -1) {
                out.write(buffer, 0, read);
            }
            out.close();
        }
    }
}
