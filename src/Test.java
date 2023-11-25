import java.awt.EventQueue;

import javax.swing.JFrame;

public class Test {
    
    public Test () {
        JFrame frame = new JFrame("RUN_TEST");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(500, 300);
        frame.setLocationRelativeTo(null);
        frame.setVisible(true);
    }

    public static void main(String args[]) {
        EventQueue.invokeLater(new Runnable() {
            @Override
            public void run() {
                new Test();
            }
        });
    }
}
