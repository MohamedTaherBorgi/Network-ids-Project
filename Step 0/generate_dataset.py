from capture.capture_engine import CaptureEngine
from processing.feature_extractor import extract_features

def main():
    engine = CaptureEngine()

    print("Collecting dataset... Press Ctrl+C to stop.")

    try:
        for pkt in engine.backend.stream():
            features = extract_features(pkt)
            engine._write_deep(features)
    except KeyboardInterrupt:
        print("Capture stopped.")

if __name__ == "__main__":
    main()
