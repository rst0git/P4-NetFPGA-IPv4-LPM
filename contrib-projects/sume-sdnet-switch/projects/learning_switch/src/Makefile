all:
	p4c-sdnet -o ${P4_PROJECT_NAME}.sdnet --sdnet_info .sdnet_switch_info.dat ${P4_PROJECT_NAME}.p4
	${SUME_SDNET}/bin/p4_px_tables.py commands.txt .sdnet_switch_info.dat

clean:
	rm -f *.sdnet *.tbl .sdnet_switch_info.dat

