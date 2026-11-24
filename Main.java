package darkwebcti;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVRecord;
import java.awt.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.LocalDate;
import java.time.YearMonth;
import java.time.format.DateTimeParseException;
import java.util.*;
import java.util.List;
import java.util.regex.*;
import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableRowSorter;


public class Main extends JFrame {
    private static class Record {
        String id, title, category, date, text, source, probability;
        Record(String[] v) {
            id = v[0]; title = v[1]; category = v[2]; date = v[3];
            text = v[4]; source = v[5]; probability = v[6];
        }
    }

    private final List<Record> records = new ArrayList<>();
    private final DefaultTableModel model = new DefaultTableModel(
        new String[]{"ID", "Title", "Category", "Created At", "Source", "Probability", "Risk"}, 0) {
        public boolean isCellEditable(int r, int c) { return false; }
    };
    private final JTable table = new JTable(model);
    private final JTextArea details = new JTextArea();
    private final JTextField search = new JTextField(22);
    private final JLabel status = new JLabel("Demo records loaded. Import your own CSV dataset to begin.");
    private final TableRowSorter<DefaultTableModel> sorter = new TableRowSorter<>(model);

    private static final String[] THREATS = {
        "phishing", "malware", "ransomware", "data breach", "credential theft",
        "sql injection", "denial of service", "ddos", "botnet", "vulnerability",
        "exploit", "spyware", "trojan", "keylogger", "zero day",
        "account takeover", "data leak", "credential stuffing", "suspicious login"
    };
    private static final Set<String> STOP = new HashSet<>(Arrays.asList(
        "the","a","an","and","or","but","if","then","is","are","was","were","be",
        "been","to","of","in","on","at","for","from","with","by","as","it","this",
        "that","these","those","i","you","he","she","we","they","my","your","our",
        "their","have","has","had","do","does","did","can","could","would","should",
        "will","not","no","so","than","too","very","about","what","when","where",
        "who","how","which","there","here","all","also","more","some","any"
    ));

    public Main() {
        super("Dark Web Cyber Threat Intelligence Analysis");
        setDefaultCloseOperation(EXIT_ON_CLOSE);
        setSize(1150, 720);
        setLocationRelativeTo(null);

        table.setRowSorter(sorter);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        table.setAutoCreateRowSorter(true);

        details.setEditable(false);
        details.setLineWrap(true);
        details.setWrapStyleWord(true);
        details.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 13));

        JSplitPane split = new JSplitPane(JSplitPane.VERTICAL_SPLIT,
            new JScrollPane(table), new JScrollPane(details));
        split.setResizeWeight(0.62);

        JPanel actions = new JPanel(new GridLayout(2, 5, 6, 6));
        addButton(actions, "Import CSV", this::importCsv);
        addButton(actions, "Analyze Dataset", this::analyzeDataset);
        addButton(actions, "Preprocess Text", this::preprocessSelected);
        addButton(actions, "Detect Threats", this::detectSelected);
        addButton(actions, "Classify Risk", this::classifySelected);
        addButton(actions, "Extract Entities", this::extractEntities);
        addButton(actions, "Topic Analysis", this::topicAnalysis);
        addButton(actions, "Threat Trends", this::showTrends);
        addButton(actions, "Export Report", this::exportReport);
        addButton(actions, "Clear Search", () -> search.setText(""));

        JPanel searchPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));
        searchPanel.add(new JLabel("Search records:"));
        searchPanel.add(search);
        searchPanel.add(status);

        search.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            public void insertUpdate(javax.swing.event.DocumentEvent e) { filter(); }
            public void removeUpdate(javax.swing.event.DocumentEvent e) { filter(); }
            public void changedUpdate(javax.swing.event.DocumentEvent e) { filter(); }
        });

        table.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) showSelected();
        });

        JPanel north = new JPanel(new BorderLayout(5, 5));
        north.add(actions, BorderLayout.CENTER);
        north.add(searchPanel, BorderLayout.SOUTH);
        add(north, BorderLayout.NORTH);
        add(split, BorderLayout.CENTER);

        loadDemoData();
        refreshTable();
    }

    private void addButton(JPanel panel, String name, Runnable action) {
        JButton b = new JButton(name);
        b.addActionListener(e -> action.run());
        panel.add(b);
    }

    private void loadDemoData() {
        records.clear();
        records.add(new Record(new String[]{"D001","Suspicious login report","Account Security",
            "2026-01-12","Several users reported suspicious login attempts and possible credential stuffing activity.",
            "Demo","0.82"}));
        records.add(new Record(new String[]{"D002","Phishing awareness advisory","Phishing",
            "2026-02-04","A public advisory describes phishing emails impersonating a service provider.",
            "Demo","0.91"}));
        records.add(new Record(new String[]{"D003","Software vulnerability notice","Vulnerability",
            "2026-02-19","A security notice discusses a software vulnerability and recommends applying the vendor update.",
            "Demo","0.65"}));
        records.add(new Record(new String[]{"D004","Data exposure news summary","Data Breach",
            "2026-03-08","A public report describes a data breach and recommends password resets and account monitoring.",
            "Demo","0.76"}));
    }

    private void refreshTable() {
        model.setRowCount(0);
        for (Record r : records) {
            model.addRow(new Object[]{r.id, r.title, r.category, r.date, r.source,
                r.probability, riskFor(r.text)});
        }
        status.setText(records.size() + " records loaded.");
        if (!records.isEmpty()) table.setRowSelectionInterval(0, 0);
    }

    private void filter() {
        String q = search.getText().trim();
        sorter.setRowFilter(q.isEmpty() ? null :
            RowFilter.regexFilter("(?i)" + Pattern.quote(q)));
        status.setText(table.getRowCount() + " matching records.");
    }

    private void importCsv() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Choose a CSV dataset");
        chooser.setFileFilter(new javax.swing.filechooser.FileNameExtensionFilter("CSV files", "csv"));
        if (chooser.showOpenDialog(this) != JFileChooser.APPROVE_OPTION) return;

        try {
            List<Record> imported = readCsv(chooser.getSelectedFile().toPath());
            if (imported.isEmpty()) {
                JOptionPane.showMessageDialog(this, "No data rows were found in the CSV file.");
                return;
            }
            records.clear();
            records.addAll(imported);
            search.setText("");
            refreshTable();
            JOptionPane.showMessageDialog(this, "Imported " + records.size() + " records.");
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Could not import CSV:\n" + ex.getMessage(),
                "Import error", JOptionPane.ERROR_MESSAGE);
        }
    }

    // Supports quoted CSV fields and commas inside quoted text.
    private List<String> parseCsvLine(String line) {
        List<String> values = new ArrayList<>();
        StringBuilder field = new StringBuilder();
        boolean quoted = false;
        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (c == '"') {
                if (quoted && i + 1 < line.length() && line.charAt(i + 1) == '"') {
                    field.append('"'); i++;
                } else quoted = !quoted;
            } else if (c == ',' && !quoted) {
                values.add(field.toString().trim());
                field.setLength(0);
            } else field.append(c);
        }
        values.add(field.toString().trim());
        return values;
    }

    private List<Record> readCsv(Path path) throws IOException {
        List<String> lines = Files.readAllLines(path, StandardCharsets.UTF_8);
        if (lines.isEmpty()) return Collections.emptyList();
        List<String> header = parseCsvLine(lines.get(0));
        Map<String,Integer> index = new HashMap<>();
        for (int i = 0; i < header.size(); i++)
            index.put(header.get(i).trim().toLowerCase(Locale.ROOT), i);

        String[] required = {"id","title","category","created_at","full_text"};
        for (String col : required)
            if (!index.containsKey(col)) throw new IOException("Missing required column: " + col);

        List<Record> result = new ArrayList<>();
        for (int n = 1; n < lines.size(); n++) {
            if (lines.get(n).trim().isEmpty()) continue;
            List<String> row = parseCsvLine(lines.get(n));
            String[] v = new String[7];
            v[0] = field(row,index,"id");
            v[1] = field(row,index,"title");
            v[2] = field(row,index,"category");
            v[3] = field(row,index,"created_at");
            v[4] = field(row,index,"full_text");
            v[5] = "Imported";
            v[6] = field(row,index,"probability");
            result.add(new Record(v));
        }
        return result;
    }

    private String field(List<String> row, Map<String,Integer> idx, String key) {
        Integer i = idx.get(key);
        return i == null || i >= row.size() ? "" : row.get(i);
    }

    private Record selected() {
        int view = table.getSelectedRow();
        if (view < 0) {
            JOptionPane.showMessageDialog(this, "Please select a record first.");
            return null;
        }
        return records.get(table.convertRowIndexToModel(view));
    }

    private void showSelected() {
        Record r = selectedQuietly();
        if (r == null) return;
        details.setText("TITLE: " + r.title + "\nCATEGORY: " + r.category +
            "\nDATE: " + r.date + "\nSOURCE: " + r.source +
            "\nPROBABILITY: " + r.probability + "\nRISK: " + riskFor(r.text) +
            "\n\nFULL TEXT:\n" + r.text);
    }

    private Record selectedQuietly() {
        int view = table.getSelectedRow();
        return view < 0 ? null : records.get(table.convertRowIndexToModel(view));
    }

    private String preprocess(String text) {
        String cleaned = text.toLowerCase(Locale.ROOT).replaceAll("[^a-z0-9 ]", " ");
        StringBuilder out = new StringBuilder();
        for (String word : cleaned.split("\\s+"))
            if (!word.isBlank() && !STOP.contains(word)) out.append(word).append(' ');
        return out.toString().trim();
    }

    private List<String> matchedThreats(String text) {
        List<String> found = new ArrayList<>();
        String lower = text.toLowerCase(Locale.ROOT);
        for (String keyword : THREATS)
            if (lower.contains(keyword)) found.add(keyword);
        return found;
    }

    private String riskFor(String text) {
        int count = matchedThreats(text).size();
        if (count >= 3) return "HIGH";
        if (count >= 1) return "MEDIUM";
        return "LOW";
    }

    private void preprocessSelected() {
        Record r = selected();
        if (r != null) details.setText("PREPROCESSED TEXT:\n" + preprocess(r.text));
    }

    private void detectSelected() {
        Record r = selected();
        if (r == null) return;
        List<String> found = matchedThreats(r.text);
        details.setText("THREAT KEYWORD ANALYSIS\n\n" +
            (found.isEmpty() ? "No configured threat keywords found." : String.join("\n", found)));
    }

    private void classifySelected() {
        Record r = selected();
        if (r != null) details.setText("RISK CLASSIFICATION\n\nRisk level: " +
            riskFor(r.text) + "\nMatched keywords: " + matchedThreats(r.text).size() +
            "\n\nThis is a simple keyword-based research baseline, not a verified security verdict.");
    }

    private void extractEntities() {
        Record r = selected();
        if (r == null) return;
        Matcher m = Pattern.compile("\\b[A-Z][a-zA-Z0-9.-]{2,}(?:\\s+[A-Z][a-zA-Z0-9.-]{2,})*\\b").matcher(r.text);
        Set<String> entities = new LinkedHashSet<>();
        while (m.find()) entities.add(m.group());
        details.setText("BASIC ENTITY EXTRACTION\n\n" +
            (entities.isEmpty() ? "No capitalized entity-like terms found." : String.join("\n", entities)) +
            "\n\nNote: This baseline uses capitalization patterns, not a trained NER model.");
    }

    private Map<String,Integer> wordFrequencies() {
        Map<String,Integer> freq = new HashMap<>();
        for (Record r : records)
            for (String word : preprocess(r.title + " " + r.category + " " + r.text).split("\\s+"))
                if (word.length() > 2) freq.merge(word, 1, Integer::sum);
        return freq;
    }

    private void topicAnalysis() {
        List<Map.Entry<String,Integer>> entries = new ArrayList<>(wordFrequencies().entrySet());
        entries.sort((a,b) -> b.getValue().compareTo(a.getValue()));
        StringBuilder out = new StringBuilder("BASIC TOPIC / TERM FREQUENCY ANALYSIS\n\n");
        int limit = Math.min(15, entries.size());
        for (int i = 0; i < limit; i++)
            out.append(i + 1).append(". ").append(entries.get(i).getKey())
                .append(" — ").append(entries.get(i).getValue()).append(" occurrences\n");
        out.append("\nThis is a frequency-based baseline, not full LDA topic modelling.");
        details.setText(out.toString());
    }

    private void analyzeDataset() {
        if (records.isEmpty()) return;
        int high = 0, medium = 0, low = 0;
        Map<String,Integer> categories = new TreeMap<>();
        for (Record r : records) {
            String risk = riskFor(r.text);
            if (risk.equals("HIGH")) high++;
            else if (risk.equals("MEDIUM")) medium++;
            else low++;
            categories.merge(r.category.isBlank() ? "Unspecified" : r.category, 1, Integer::sum);
        }
        StringBuilder out = new StringBuilder("DATASET SUMMARY\n\nTotal records: " + records.size() +
            "\nHigh risk: " + high + "\nMedium risk: " + medium + "\nLow risk: " + low +
            "\n\nCATEGORY COUNTS\n");
        for (Map.Entry<String,Integer> e : categories.entrySet())
            out.append(e.getKey()).append(": ").append(e.getValue()).append("\n");
        details.setText(out.toString());
    }

    private void showTrends() {
        Map<String,Integer> months = new TreeMap<>();
        for (Record r : records) {
            try {
                String month = YearMonth.from(LocalDate.parse(r.date)).toString();
                months.merge(month, 1, Integer::sum);
            } catch (DateTimeParseException ignored) {
                months.merge("Unknown date", 1, Integer::sum);
            }
        }
        StringBuilder out = new StringBuilder("TEMPORAL RECORD TREND\n\n");
        for (Map.Entry<String,Integer> e : months.entrySet())
            out.append(e.getKey()).append(" : ").append(e.getValue()).append(" records\n");
        out.append("\nDates should use YYYY-MM-DD for accurate monthly grouping.");
        details.setText(out.toString());
    }

    private void exportReport() {
        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new File("CTI_Analysis_Report.txt"));
        if (chooser.showSaveDialog(this) != JFileChooser.APPROVE_OPTION) return;
        try {
            StringBuilder report = new StringBuilder();
            report.append("DARK WEB CYBER THREAT INTELLIGENCE ANALYSIS\n");
            report.append("Generated: ").append(new Date()).append("\n\n");
            report.append("Total records: ").append(records.size()).append("\n");
            int high = 0, med = 0, low = 0;
            for (Record r : records) {
                String risk = riskFor(r.text);
                if (risk.equals("HIGH")) high++;
                else if (risk.equals("MEDIUM")) med++;
                else low++;
            }
            report.append("High risk: ").append(high).append("\nMedium risk: ")
                .append(med).append("\nLow risk: ").append(low).append("\n\nRECORD DETAILS\n");
            for (Record r : records) {
                report.append("\n[").append(r.id).append("] ").append(r.title)
                    .append("\nCategory: ").append(r.category)
                    .append("\nDate: ").append(r.date)
                    .append("\nRisk: ").append(riskFor(r.text))
                    .append("\nThreat terms: ").append(matchedThreats(r.text))
                    .append("\nText: ").append(r.text).append("\n");
            }
            Files.write(chooser.getSelectedFile().toPath(), report.toString().getBytes(StandardCharsets.UTF_8));
            JOptionPane.showMessageDialog(this, "Report exported successfully.");
        } catch (IOException ex) {
            JOptionPane.showMessageDialog(this, "Export failed: " + ex.getMessage());
        }
    }    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new Main().setVisible(true));
    }
}
