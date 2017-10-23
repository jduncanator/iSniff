all: isniff

isniff:
	$(CC) -g -o isniff src/*.c -Iinclude -limobiledevice -lplist

clean:
	rm -f isniff
