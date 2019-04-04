#include <stdio.h>
#include <stdlib.h>

typedef struct ipmi_entity {
	uint8_t		ie_type;
	uint8_t		ie_instance;
	uint8_t		ie_children;
	boolean_t	ie_logical;
} ipmi_entity_t;

typedef struct ipmi_sdr {
	uint16_t	is_id;
	uint8_t		is_version;
	uint8_t		is_type;
	uint8_t		is_length;
	uint8_t		is_record[1];
} ipmi_sdr_t;


