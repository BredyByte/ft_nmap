TARGET = ft_nmap

OBJ_PATH = obj
SRC_PATH = src
INC_PATH = inc

HEADERS = -I ./$(INC_PATH)

CC = gcc
CFLAGS =  -Wall -Wextra -Werror -g -pthread

REMOVE = rm -rf

SRC =	main.c \
		utils.c \
		args.c \
		nmap.c \

OBJ = $(addprefix $(OBJ_PATH)/, $(SRC:.c=.o))

all: $(TARGET)

$(TARGET): $(OBJ)
	@$(CC) $(CFLAGS) $(OBJ) $(HEADERS) -o $@
	@echo "ft_nmap is compiled!"

$(OBJ_PATH)/%.o: $(SRC_PATH)/%.c $(INC_PATH)/*.h
	@mkdir -p $(OBJ_PATH)
	@$(CC) $(CFLAGS) -c $< -o $@ $(HEADERS)

clean:
	@$(REMOVE) $(OBJ_PATH)
	@echo "ft_namp is cleaned!"

fclean:
	@$(REMOVE) $(OBJ_PATH)
	@$(REMOVE) $(TARGET)
	@echo "ft_nmap is fcleaned!"

re: fclean all
