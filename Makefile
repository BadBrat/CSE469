# Makefile for bchoc
TARGET = bchoc

all: $(TARGET)

$(TARGET): $(TARGET).py
	@cp $(TARGET).py $(TARGET)
	@chmod +x $(TARGET)

clean:
	@rm -f $(TARGET)
