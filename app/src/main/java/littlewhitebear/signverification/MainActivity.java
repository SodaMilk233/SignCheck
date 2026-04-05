package littlewhitebear.signverification;

import android.app.Activity;
import android.os.Bundle;

public class MainActivity extends Activity {

    static {
        System.loadLibrary(new String(new char[]{'S', 'i', 'g', 'n', 'V', 'e', 'r', 'i', 'f', 'y'}));
    }

    @Override
    protected native void onCreate(Bundle savedInstanceState);

}