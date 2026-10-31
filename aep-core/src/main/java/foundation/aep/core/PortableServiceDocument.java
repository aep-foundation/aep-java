package foundation.aep.core;

import java.util.List;

public record PortableServiceDocument(
        String format, String version, String id, List<Block> summary, List<Block> content) {
    public PortableServiceDocument {
        summary = Copies.nullableList(summary);
        content = Copies.nullableList(content);
    }

    public List<Block> summary() {
        return summary == null ? null : List.copyOf(summary);
    }

    public List<Block> content() {
        return content == null ? null : List.copyOf(content);
    }

    public record Block(String type, String text, String title, List<Block> blocks, List<String> items) {
        public Block {
            blocks = Copies.nullableList(blocks);
            items = Copies.nullableList(items);
        }

        public List<Block> blocks() {
            return blocks == null ? null : List.copyOf(blocks);
        }

        public List<String> items() {
            return items == null ? null : List.copyOf(items);
        }
    }
}
