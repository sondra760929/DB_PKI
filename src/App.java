import java.awt.*;
import java.awt.event.*;
import com.ktnet.pdf.security.LtvLevel;
import com.ktnet.pdf.security.PdfPkcs7;
import com.ktnet.pdf.security.PdfTimeStamp;
import com.ktnet.pdf.security.exception.PdfSignatureException;
import com.lowagie.text.*;
import com.lowagie.text.Font;
import com.lowagie.text.Image;
import com.lowagie.text.Rectangle;
import com.lowagie.text.pdf.*;
import com.lowagie.text.pdf.codec.PngImage;
import com.oss.asn1.DecodeFailedException;
import com.oss.asn1.DecodeNotSupportedException;
import com.oss.asn1.EncodeFailedException;
import com.oss.asn1.EncodeNotSupportedException;
import junit.framework.Assert;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.util.StreamParsingException;
import tradesign.crypto.provider.CaPubs;
import tradesign.crypto.provider.JeTS;
import tradesign.pki.asn1.ASN1Exception;
import tradesign.pki.oss.tsp.TSPTimeStampToken;
import tradesign.pki.pkcs.PKCSException;
import tradesign.pki.util.FileUtil;
import tradesign.pki.util.JetsUtil;
import tradesign.pki.x509.X509ExtensionException;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CRLException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JDialog;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JProgressBar;
import javax.swing.JRadioButton;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.SwingWorker;
import javax.swing.UIManager;
import javax.swing.UnsupportedLookAndFeelException;
import javax.swing.border.CompoundBorder;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.table.DefaultTableCellRenderer;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableColumnModel;

class MyDialog extends JDialog{
    JTextField tf = new JTextField(10);
    JButton jb = new JButton("OK");

    public MyDialog(JFrame frame, String title){
        super(frame, title);
        setLayout(new FlowLayout());
        add(tf);
        add(jb);
        setSize(200, 100);
        jb.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e){
                setVisible(false);
            }
        });
    }
}

   
public class App {
    public boolean useTSA = false;
    // files
    public String pwd_file = "./data/pwd.txt";
    public String dir = "./data/test/" + getClass().getSimpleName();
    public String ORIGINAL = "./data/test/hello.pdf";

    public String SIGNED = dir + "/signature.pdf";
    public String SIGNED2 = dir + "/signature2.pdf";
    public String SIGNED_WITH_TST = dir + "/signature_with_tst.pdf";
    // public String SIGNED_WITH_TST = dir + "/123.pdf";

    public String REVISION = dir + "/revision.pdf";

    // signature
    private static String sigName = "DocuScan";
    public static final String IMAG_PATH = "data/img/rubber_stamp.jpg";

    // algorithms
    private String HASH_ALGORITHM = "SHA256";
    private String TST_HASH_ALGORITHM = "SHA256";

    // tsa

    // private String TSA_URL =
    // "https://tsatest.tradesign.net:8093/service/timestamp/issue";
    // "http://tsa.tradesign.net:8090/service/timestamp/issue"
    // "https://tsa.tradesign.net:8093/service/timestamp/issue"
    private String TSA_URL = "http://tsa.tradesign.net:8090/service/timestamp/issue";
    private String TSA_ID = "dgbook";
    private String TSA_PWD = "dgbook_pwd";

    // cert
    private static final String CERT_PATH = "data/config/ServerCert/signCert.der";
    private static final String PRIV_PATH = "data/config/ServerCert/signPri.key";
    private String PRIV_PWD = "*ghkdwkdrns7879";
    public static byte[] encPrivateKey;
    public static byte[] signerCert;
    public static char[] signerCertPassword;

    // prop
    private static String PROP_PATH = "data/config/tradesign3280.properties";
    private static final String TSA_CERT_PATH = "data/config/ServerCert/TradeSign_TSA.der";
    // private static final String TSA_CERT_PATH =
    // "data/config/ServerCert/TradeSign_TSA4.der";

    // private String UNSIGNED_ATTR_OID = "1.2.410.200012.1.3.1.1"; // 시큐센 생체 정보
    private String UNSIGNED_ATTR_OID = "1.2.410.200012.1.1.501"; // 디지북 전자문서 전용 OID
        
    public String testOutputDir = "./data/test/" + getClass().getSimpleName();

    public static String getPrintStackTrace(Exception e) {
         
        StringWriter errors = new StringWriter();
        e.printStackTrace(new PrintWriter(errors));
         
        return errors.toString();
         
    }

    /**
     * 
     * @param src
     *                   원본 PDF 경로
     * @param dest
     *                   전자서명될 PDF 경로
     * @param inlucdeTST
     *                   타임스탬프토큰 포함 여부
     * @param withText
     *                   전자서명 이미지에 서명 텍스트 정보 포함 여부
     * @param append
     *                   원본이 이미 전자서명 되어 있는경우 true(다중서명)
     * @param sigName
     *                   전자서명 이름. 다중서명시 각각 다른것으로 해야 함.
     * @throws Exception
     */
    public void signPdf(String src, String dest, boolean inlucdeTST, boolean withText, boolean append, String sigName)
            throws Exception {

        FileInputStream fin = new FileInputStream(src);
        PdfReader reader = new PdfReader(fin, "!2qwsaqwsa".getBytes());

        Rectangle page_size = reader.getPageSize(1);
        
        // int contentEstimated = 20240;
        PdfPkcs7 pdfPkcs7Gen = new PdfPkcs7(reader, append);
        // pdfPkcs7Gen.setContentEstimated(contentEstimated);

        pdfPkcs7Gen.setSigner(signerCert, encPrivateKey, signerCertPassword);

        // HSM 사용시
        // PrivateKey =signerKey = HSM.getPrivateKey();
        // pdfPkcs7Gen.setSigner(signerCert, signerKey);

        /*
         * static final String fontNames[] = { "Courier", "Courier-Bold",
         * "Courier-Oblique", "Courier-BoldOblique", "Helvetica",
         * "Helvetica-Bold", "Helvetica-Oblique", "Helvetica-BoldOblique",
         * "Times-Roman", "Times-Bold", "Times-Italic", "Times-BoldItalic",
         * "Symbol", "ZapfDingbats"};
         */

        // 페이지 왼쪽 아래 코너 좌표 : (0,0)
        // Rectangle imgRect = new Rectangle(400, 700, 520, 800);
        float p_width = page_size.getWidth();
        float p_height = page_size.getHeight();
        float i_length = 50.0f;
        float mark_scale = 0.2f;
        if(p_width > i_length * 12.0f)
        {
            i_length = i_length * 2.0f;
            mark_scale = mark_scale * 2.0f;
        }

        Rectangle imgRect = new Rectangle(
            p_width - i_length - i_length, 
            p_height - i_length - i_length, 
            p_width- i_length, 
            p_height - i_length);

        // OPTION1
        // pkcs7.setVisibleSignature(Image.getInstance(RESOURCE), 1, imgRect);

        // OPTION2
        FileInputStream fisImg = inlucdeTST ? new FileInputStream("data/img/dgbook_tsa.png") : new FileInputStream("data/img/dgbook.png");
        byte[] imgBytes = IOUtils.toByteArray(fisImg);
        Image img = PngImage.getImage(imgBytes);

        pdfPkcs7Gen.setVisibleSignature(img, 1, imgRect);

        // layer1 : adobe 검증성공 이미지 크기/사이즈 설정.
        TransformMatrix layer1TransMatrix = new TransformMatrix();
        layer1TransMatrix.setXTrans(i_length / 4.0f);
        layer1TransMatrix.setYTrans(i_length / 5.0f);
        layer1TransMatrix.setXScale(mark_scale);
        layer1TransMatrix.setYScale(mark_scale);
        pdfPkcs7Gen.setLayer1TransMatrix(layer1TransMatrix);

        // layer3 : adobe 검증실패 이미지 크기/사이즈 설정.
        TransformMatrix layer3TransMatrix = new TransformMatrix();
        layer3TransMatrix.setXTrans(i_length / 4.0f);
        layer3TransMatrix.setYTrans(i_length / 5.0f);
        layer3TransMatrix.setXScale(mark_scale);
        layer3TransMatrix.setYScale(mark_scale);
        pdfPkcs7Gen.setLayer3TransMatrix(layer3TransMatrix);

        if (withText) {
            Rectangle textRect = new Rectangle(
                p_width- i_length - i_length, 
                p_height - i_length - i_length - (i_length / 3.0f), 
                p_width- i_length, 
                p_height - i_length - i_length);
            SimpleDateFormat sd = new SimpleDateFormat("날짜 : yyyy.MM.dd HH:mm:ss z");
            String text = sd.format(new Date());

            BaseFont objBaseFont = BaseFont.createFont("data/font/gulim.ttc,0", BaseFont.IDENTITY_H, BaseFont.EMBEDDED);
            Font font = new Font(objBaseFont, 6);
            // Font font = FontFactory.getFont("Helvetica", 11);

            pdfPkcs7Gen.setVisibleText(text, font, textRect);
        }

        if (inlucdeTST) {
            pdfPkcs7Gen.setTSAInfo(TSA_URL, TSA_ID, TSA_PWD, TST_HASH_ALGORITHM);
        }

        // unsigned attribute
        ASN1EncodableVector unauthAttributes = new ASN1EncodableVector();
        unauthAttributes.add(new DERSequence(getUnsignedAttr()));
        // unauthAttributes.add(new DERSequence(getUnsignedAttr()));
        pdfPkcs7Gen.setUnsignedAttrs(unauthAttributes);

        // make
        FileOutputStream fout = new FileOutputStream(dest);
        pdfPkcs7Gen.make(fout, sigName, HASH_ALGORITHM);
    }

    private ASN1EncodableVector getUnsignedAttr() throws IOException {
        DEROctetString o = new DEROctetString("bio info".getBytes());
        ASN1EncodableVector v = new ASN1EncodableVector();
        v.add(new ASN1ObjectIdentifier(UNSIGNED_ATTR_OID));
        v.add(new DERSet(o.toASN1Primitive()));
        return v;
    }

    public void verify(String src) throws Exception {

        System.out.println("**************** verify results for " + src + " ******************");

        FileInputStream fin = new FileInputStream(src);

        PdfReader reader = new PdfReader(fin);
        AcroFields af = reader.getAcroFields();
        ArrayList<String> sigNames = reader.getAcroFields().getSignatureNames();

        for (int i = 0; i < sigNames.size(); i++) {
            PdfName subFilter = af.getSubFilter(sigNames.get(i));
            // PKCS7 With or Without Timestamp
            if (subFilter.compareTo(PdfName.ADBE_PKCS7_DETACHED) == 0) {
                System.out.println("* signautre name : " + sigNames.get(i) + "\n");
                verifyPkcs7(reader, sigNames.get(i));
                // Timestamp Only
            } else if (subFilter.compareTo(PdfName.ETSI_RFC3161) == 0) {
                System.out.println("* signautre name : " + sigNames.get(i) + "\n");
                verifyEtsi(reader, sigNames.get(i));
            } else {
                throw new UnsupportedOperationException(subFilter + "는 지원하지 않습니다");
            }
        }
    }

    private void verifyPkcs7(PdfReader reader, String sigName) throws DecodeFailedException, EncodeFailedException,
            NoSuchAlgorithmException, DecodeNotSupportedException, IOException, PKCSException,
            EncodeNotSupportedException, SignatureException, CertificateEncodingException, CertificateException,
            StreamParsingException, PdfSignatureException, InvalidKeyException, CRLException, NoSuchProviderException {

        PdfPkcs7 pkcs7 = new PdfPkcs7(reader);

        X509Certificate signerCert = pkcs7.getSigningCertificate(sigName);
        System.out.println("* PKCS7 Signer : " + signerCert);
        signerCert.getIssuerDN(); // 서명한 인증서 DN값
        // System.out.println("* 경로 검증 : ");
        // CertPathValidate.validate(signerCert);
        System.out.println("* PKCS7 서명값 검증 : " + pkcs7.verify(sigName) + "\n");
        Assert.assertEquals(true, pkcs7.verify(sigName));

        /*
         * //unsigned attr
         * ASN1Set attributeValues = pkcs7.getUnsignedAttrs(sigName, UNSIGNED_ATTR_OID);
         * DEROctetString octet = (DEROctetString)
         * attributeValues.getObjectAt(0).getDERObject();
         * String unsignedAttrValue = new String(octet.getOctets());
         * System.out.println("* PKCS7 UnsignedAttr Value : " + unsignedAttrValue);
         */

        // Token
        if (pkcs7.hasTimeStampToken(sigName)) {
            X509Certificate tokenSignerCert = pkcs7.getTimeStampTokenCertificate(sigName);
            // IOUtils.write(tokenSignerCert.getEncoded(), new
            // FileOutputStream("tradesign_token_signer.der"));
            System.out.println("* Token Signer : " + tokenSignerCert);
            // System.out.println("* 경로 검증 : ");
            // CertPathValidate.validate(tokenSignerCert);

            TSPTimeStampToken token = pkcs7.getTimeStampToken(sigName);
            System.out.println("* Token : " + token + "\n");
            System.out.println("* Token 서명 검증 : " + pkcs7.verifyTimestamp(sigName) + "\n");
            Assert.assertEquals(true, pkcs7.verifyTimestamp(sigName));
            System.out.println("* Token HASH(PDF대비) 검증 : " + pkcs7.verifyTimestampImprint(sigName) + "\n");
            Assert.assertEquals(true, pkcs7.verifyTimestampImprint(sigName));
            System.out.println("* Token Date : " + pkcs7.getTimeStampDate(sigName) + "\n");
            System.out.println("* Token hash : " + JetsUtil.toString(token.getTSTInfo().getHashedMessage()) + "\n");
        }

        OutputStream output = new ByteArrayOutputStream();
        pkcs7.extractRevision(output, sigName);

    }

    public void verifyEtsi(PdfReader reader, String sigName)
            throws GeneralSecurityException, IOException, DecodeFailedException, EncodeFailedException,
            DecodeNotSupportedException, PKCSException, EncodeNotSupportedException, StreamParsingException {
        PdfTimeStamp pdfTimeStamp = new PdfTimeStamp(reader);
        OutputStream output = new ByteArrayOutputStream();
        pdfTimeStamp.extractRevision(output, sigName);
        System.out.println("* Token Date : " + pdfTimeStamp.getTimeStampDate(sigName) + "\n");

        X509Certificate tokenCert = pdfTimeStamp.getTimeStampTokenCertificate(sigName);
        System.out.println("* Token Cert : " + tokenCert);
        // System.out.println("* 경로검증 : ");
        // CertPathValidate.validate(tokenCert);
        System.out.println();

        System.out.println("* Token 서명 검증 : " + pdfTimeStamp.verify(sigName) + "\n");
        System.out.println("* Token HASH(PDF대비) 검증 : " + pdfTimeStamp.verifyTimestampImprint(sigName) + "\n");
        System.out.println("* Token HASH : "
                + JetsUtil.toString(pdfTimeStamp.getTimeStampToken(sigName).getTSTInfo().getHashedMessage()));
        org.junit.Assert.assertEquals(true, pdfTimeStamp.verify(sigName));
    }

    public void saveOriginDir(String origin_dir) {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter("origin.dir", false))) {
            writer.write(origin_dir);
            writer.close();
        } catch (IOException ex) {
            ex.printStackTrace();
        }
    }

    public void saveTargetDir(String target_dir) {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter("target.dir", false))) {
            writer.write(target_dir);
            writer.close();
        } catch (IOException ex) {
            ex.printStackTrace();
        }
    }

    public String readOriginDir() {
        BufferedReader reader;
        String line = "";
        try {
            reader = new BufferedReader(new FileReader("origin.dir"));
            line = reader.readLine();
            reader.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return line;
    }

    public boolean readPWD(){
        BufferedReader reader;
        String line = "";
        try {
            reader = new BufferedReader(new FileReader(pwd_file));
            line = reader.readLine();
            reader.close();
            PRIV_PWD = line;
            return true;
        } catch (IOException e) {
            e.printStackTrace();
            return false;
        }
    }

    public String readTargetDir() {
        BufferedReader reader;
        String line = "";
        try {
            reader = new BufferedReader(new FileReader("target.dir"));
            line = reader.readLine();
            reader.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return line;
    }

    public App() {
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
        } catch (ClassNotFoundException | InstantiationException | IllegalAccessException
                | UnsupportedLookAndFeelException ex) {
            ex.printStackTrace();
        }

        try {
            JeTS.installProvider(PROP_PATH);
        } catch (X509ExtensionException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (CertificateException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (ASN1Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        try {
            JeTS.setCapubs(CaPubs.all);
        } catch (X509ExtensionException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (CertificateException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (ASN1Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        Security.addProvider(new BouncyCastleProvider());

        try {
            encPrivateKey = IOUtils.toByteArray(new FileInputStream(PRIV_PATH));
        } catch (FileNotFoundException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        try {
            signerCert = IOUtils.toByteArray(new FileInputStream(CERT_PATH));
        } catch (FileNotFoundException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        readPWD();
        signerCertPassword = PRIV_PWD.toCharArray();

        // File file = new File(dir);
        // if (!file.exists())
        // file.mkdirs();

        // signatures.createPdf(signatures.ORIGINAL);

        // String userDirectory = new File("").getAbsolutePath();
        // System.out.println(userDirectory);

        JFrame frame = new JFrame("DB_KPI");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        PDF_PKI_Pane pki_pane = new PDF_PKI_Pane(this);
        frame.add(pki_pane);
        frame.pack();
        frame.setLocationRelativeTo(null);
        frame.setVisible(true);
    }

    public class PDF_PKI_Pane extends JPanel {

        private DirectoryPane directoryPane;
        private PDFFilesPane pDFFilesPane;
        private ActionPane actionPane;

        public PDF_PKI_Pane(App app) {
            setLayout(new GridBagLayout());
            GridBagConstraints gbc = new GridBagConstraints();
            gbc.gridx = 0;
            gbc.gridy = 0;
            gbc.weightx = 1;
            gbc.weighty = 0;
            gbc.anchor = GridBagConstraints.WEST;
            gbc.fill = GridBagConstraints.BOTH;
            gbc.insets = new Insets(4, 4, 4, 4);

            pDFFilesPane = new PDFFilesPane(app);
            directoryPane = new DirectoryPane(app, pDFFilesPane);
            add(directoryPane, gbc);
            gbc.gridy++;
            add(pDFFilesPane, gbc);

            gbc.gridy = 0;
            gbc.gridx++;
            gbc.gridheight = GridBagConstraints.REMAINDER;
            gbc.fill = GridBagConstraints.VERTICAL;
            gbc.weighty = 1;
            gbc.weightx = 0;
            add((actionPane = new ActionPane(app, pDFFilesPane)), gbc);
        }
    }

    public class DirectoryPane extends JPanel {
        private JTextField dirOrigin;
        private JTextField dirTarget;
        private PDFFilesPane _pdf_pane;
        private App current_app;

        public DirectoryPane(App _app, PDFFilesPane pdf_pane) {
            current_app = _app;
            this._pdf_pane = pdf_pane;
            setLayout(new GridBagLayout());
            GridBagConstraints gbc = new GridBagConstraints();
            gbc.gridx = 0;
            gbc.gridy = 0;
            gbc.anchor = GridBagConstraints.WEST;

            add(new JLabel("PDF Folder [Origin]: "), gbc);

            gbc.gridx++;
            gbc.gridy = 0;
            gbc.weightx = 1;
            gbc.fill = GridBagConstraints.HORIZONTAL;

            add((dirOrigin = new JTextField(10)), gbc);

            JButton btn1 = new JButton("...");
            btn1.addActionListener(e -> {
                String pref_origin = current_app.readOriginDir();
                JFileChooser jfc = new JFileChooser(pref_origin);
                jfc.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
                int result = jfc.showDialog(this, null);
                if (result == JFileChooser.APPROVE_OPTION) {
                    File dir = jfc.getSelectedFile();
                    dirOrigin.setText(dir == null ? "" : dir.getPath());
                    current_app.saveOriginDir(getOrigin());
                    _pdf_pane.setOriginDir(getOrigin());
                }
            });

            gbc.gridx++;
            gbc.gridy = 0;
            gbc.weightx = 0;
            gbc.anchor = GridBagConstraints.EAST;
            add(btn1, gbc);

            gbc.gridx = 0;
            gbc.gridy = 1;
            gbc.anchor = GridBagConstraints.WEST;

            add(new JLabel("PDF Folder [Target]: "), gbc);

            gbc.gridx++;
            gbc.weightx = 1;
            gbc.fill = GridBagConstraints.HORIZONTAL;

            add((dirTarget = new JTextField(10)), gbc);

            JButton btn2 = new JButton("...");
            btn2.addActionListener(e -> {
                String pref_target = current_app.readTargetDir();
                JFileChooser jfc = new JFileChooser(pref_target);
                jfc.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
                int result = jfc.showDialog(this, null);
                if (result == JFileChooser.APPROVE_OPTION) {
                    File dir = jfc.getSelectedFile();
                    dirTarget.setText(dir == null ? "" : dir.getPath());
                    current_app.saveTargetDir(getTarget());
                    _pdf_pane.setTargetDir(getTarget());
                }
            });

            gbc.gridx++;
            gbc.weightx = 0;
            gbc.anchor = GridBagConstraints.EAST;
            add(btn2, gbc);
        }

        public String getOrigin() {
            return dirOrigin.getText();
        }

        public void setOrigin(String name) {
            dirOrigin.setText(name);
        }

        public String getTarget() {
            return dirTarget.getText();
        }

        public void setTarget(String name) {
            dirTarget.setText(name);
        }

    }

    public class PDFFilesPane extends JPanel {

        private DefaultTableModel model;
        private JTable table;
        private JScrollPane scrolledTable;
        private String targetDirectory;
        private String originDirectory;
        private App current_app;
        private JProgressBar jProgressBar1;

        public PDFFilesPane(App _app) {
            current_app = _app;
            setLayout(new BorderLayout());
            String header[] = { "No", "Path", "PKI" };
            model = new DefaultTableModel(header, 0); // header추가, 행은 0개 지정

            jProgressBar1 = new JProgressBar(JProgressBar.HORIZONTAL, 0, 100);
            jProgressBar1.setMinimumSize(new Dimension(30, 50));
            add(jProgressBar1, BorderLayout.NORTH); // 가운데에 JTable 추가

            table = new JTable(model);
            table.setSelectionMode(ListSelectionModel.MULTIPLE_INTERVAL_SELECTION);
            scrolledTable = new JScrollPane(table); // 스크롤 될 수 있도록 JScrollPane 적용
            scrolledTable.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10)); // 너무 붙어있어서 가장자리 띄움(padding)
            add(scrolledTable, BorderLayout.CENTER); // 가운데에 JTable 추가
            table.setRowHeight(30);
            // table.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
            DefaultTableCellRenderer cellRenderer = new DefaultTableCellRenderer();
            cellRenderer.setHorizontalAlignment(JLabel.CENTER);
            table.getColumnModel().getColumn(0).setCellRenderer(cellRenderer);
            table.getColumnModel().getColumn(0).setMaxWidth(100);
            table.getColumnModel().getColumn(2).setMaxWidth(100);
        }

        public Set<String> listFilesUsingFilesList(String dir) throws IOException {
            try (Stream<Path> stream = Files.walk(Paths.get(dir))) {
                return stream
                        .filter(file -> !Files.isDirectory(file))
                        // .map(Path::getFileName)
                        .map(Path::toString)
                        .filter(f -> f.endsWith("pdf"))
                        .collect(Collectors.toSet());
            }
        }

        public String getFile() {
            String sel_file_path = "";

            int sel_row = table.getSelectedRow();
            if (sel_row > -1) {
                sel_file_path = table.getValueAt(sel_row, 1).toString();
            }
            return sel_file_path;
        }

        public void setOriginDir(String dir_path) {
            originDirectory = dir_path;
            try {
                Set<String> file_list = listFilesUsingFilesList(dir_path);
                int file_index = 1;
                model.setRowCount(0);
                for (String file_path : file_list) {
                    model.addRow(new Object[] { Integer.toString(file_index), file_path, "" });
                    file_index++;
                }

                table.updateUI();
            } catch (IOException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
        }

        public void setTargetDir(String dir_path) {
            targetDirectory = dir_path;
        }

        public String getTargetDir() {
            return targetDirectory;
        }

        public void runSelectFile() {
            int sel_row = table.getSelectedRow();
            try {
                if (sel_row > -1) {
                    String sel_file_path = table.getValueAt(sel_row, 1).toString();
                    File f = new File(sel_file_path);
                    if (f.exists()) {
                        String target_path = sel_file_path;
                        target_path = target_path.replace(originDirectory, targetDirectory);
                        File p_f = new File(target_path);
                        String target_temp_path = p_f.getParentFile().toString();
                        p_f = new File(target_temp_path);
                        p_f.mkdirs();
                        current_app.signPdf(sel_file_path, target_path, current_app.useTSA, true, current_app.useTSA,
                                sigName);
                        table.setValueAt("O", sel_row, 2);
                    }
                }
            } catch (Exception e1) {
                // TODO Auto-generated catch block
                // e1.printStackTrace();
                String except_string = "X" + getPrintStackTrace(e1);
                table.setValueAt(except_string, sel_row, 2);
            }
        }

        public void runAll() {
            int row_count = table.getRowCount();
            final SwingWorker<Void, Void> worker = new SwingWorker<Void, Void>() {
                @Override
                protected Void doInBackground() throws Exception {
                    for (int sel_row = 0; sel_row < row_count; sel_row++) {
                        try {
                            String sel_file_path = table.getValueAt(sel_row, 1).toString();
                            String check_file = table.getValueAt(sel_row, 2).toString();
                            if (check_file != "O") {
                                File f = new File(sel_file_path);
                                if (f.exists()) {
                                    table.setValueAt("signing..", sel_row, 2);
                                    String target_path = sel_file_path;
                                    target_path = target_path.replace(originDirectory, targetDirectory);
                                    File p_f = new File(target_path);
                                    String target_temp_path = p_f.getParentFile().toString();
                                    p_f = new File(target_temp_path);
                                    p_f.mkdirs();
                                    current_app.signPdf(sel_file_path, target_path, current_app.useTSA, true,
                                            current_app.useTSA, sigName);
                                    table.setValueAt("O", sel_row, 2);
                                }
                            }
                        } catch (Exception e1) {
                            // TODO Auto-generated catch block
                            // e1.printStackTrace();
                            String except_string = "X" + getPrintStackTrace(e1);
                            table.setValueAt(except_string, sel_row, 2);
                        }
                        jProgressBar1.setValue((sel_row + 1) * 100 / row_count);
                        try {
                            Thread.sleep(20);
                        } catch (InterruptedException ex) {
                        }

                    }

                    for (int i = 0; i <= 100; i++) {
                    }
                    return null;
                }
            };
            worker.execute();

        }
    }

    public class ActionPane extends JPanel {

        private JButton btn_all, btn_select, options;
        private App current_app;
        private PDFFilesPane pdf_files;

        public ActionPane(App _app, PDFFilesPane _pdf_files) {
            current_app = _app;
            pdf_files = _pdf_files;
            setLayout(new GridBagLayout());
            GridBagConstraints gbc = new GridBagConstraints();
            gbc.gridx = 0;
            gbc.gridy = 0;
            gbc.gridwidth = GridBagConstraints.REMAINDER;
            gbc.fill = GridBagConstraints.HORIZONTAL;
            gbc.weightx = 1;
            gbc.insets = new Insets(4, 4, 4, 4);

            add((btn_all = new JButton("전체")), gbc);
            gbc.gridy++;
            add((btn_select = new JButton("선택")), gbc);
            gbc.gridy++;
            gbc.gridy++;
            JCheckBox c = new JCheckBox("TSA", false);
            add(c, gbc);
            c.addActionListener(e -> {
                current_app.useTSA = c.isSelected();
            });

            gbc.gridy++;
            gbc.weighty = 1;
            gbc.anchor = GridBagConstraints.SOUTH;
            add((options = new JButton("Options >>")), gbc);

            btn_all.addActionListener(e -> {
                pdf_files.runAll();
            });

            btn_select.addActionListener(e -> {
                pdf_files.runSelectFile();
            });
        }

    }

    public static void main(String args[]) {
        EventQueue.invokeLater(new Runnable() {
            @Override
            public void run() {
                new App();
            }
        });
    }
}