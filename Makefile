.PHONY: all clean bundle tar deb

TARGET = dist
TARGET_TAR = $(TARGET)/tar
TARGET_DEB = $(TARGET)/deb

NAME = openidserver

all:

bundle: tar deb

tar:
	rm -rf $(TARGET_TAR)/$(NAME)
	mkdir -p $(TARGET_TAR)

	cp -rt $(TARGET_TAR)/ $(NAME)
	cp -t $(TARGET_TAR)/$(NAME)/ README.md COPYING.gz
	tar czf $(TARGET_TAR)/$(NAME).tar.gz -C $(TARGET_TAR) $(NAME)

deb:

clean:
	rm -rf $(TARGET)
