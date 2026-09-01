package foundation.aep.core;

public interface AepJsonProvider {
    <T> T decode(String json, Class<T> type);

    String write(Object value);
}
