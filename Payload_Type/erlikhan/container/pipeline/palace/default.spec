x64:
    load "loader.x64.o"
        make pic +gofirst +optimize

    dfr "resolve" "ror13"

    generate $MASK 128

    push $DLL
        xor $MASK
        preplen
        link "dll"

    push $MASK
        preplen
        link "mask"

    run "pico.spec"
        link "pico"

    export
