echo "================================ Compile Golang Server to Microsoft OS ================================"
version=$(grep 'version' ../cmd/main.go | sed -n 's/.*"\(v[0-9]\.[0-9]\.[0-9]\)".*/\1/p')
name="Golyn"
releaseName="$name"_"$version"
releaseNote=$releaseName"_release_note.txt"

rm -rf releaseName releaseName.tar.gz

echo "Creating directory structure..."
mkdir "$releaseName"
mkdir "$releaseName"/var
mkdir "$releaseName"/var/log
mkdir "$releaseName"/config
mkdir "$releaseName"/certificates
mkdir "$releaseName"/static
mkdir "$releaseName"/static/html


echo "[OK] Directory structure"

echo "Copying files..."
cp ../static/favicon.ico "$releaseName"/static
cp ../static/html/index.html "$releaseName"/static/html
cp ../config/galleta_app.conf "$releaseName"/config
cp ../certificates/* "$releaseName"/certificates

echo "[OK] Copied files"

echo "Compiling..."
GOARCH=amd64 GOOS=linux go build -o "$releaseName"/golyn ../cmd/main.go

echo "[OK] Compiled"

echo "Generating $releaseNote"
nowDT=$(date +"%Y-%m-%d %H:%M:%S")
echo "Release: $name $version (Windows) $nowDT" >  "$releaseName"/"$releaseNote"

printf "\n| %-30s | %-30s | %-30s\n" " File Name" "Last Update" "Hash MD5" >> "$releaseName"/"$releaseNote"
echo "-------------------------------------------------------------------------------------------------------" >> "$releaseName"/"$releaseNote"

directory=".."
cmd="../cmd"
internal="../internal"
modules="../modules"
pkg="../pkg"

if [ -d "$directory" ]; then
    for folder in "$directory"/*; do
        if [ -d "$folder" ]; then
            if [ "$folder" == "$cmd" ] || [ "$folder" == "$internal" ] || [ "$folder" == "$modules" ] || [ "$folder" == "$pkg" ]; then
                for archivo in "$folder"/*.go; do
                    if [ -f "$archivo" ]; then
                        timestamp=$(stat -t "%Y-%m-%d %H:%M:%S" -f "%Sm" "$archivo")
                        nombre=$(basename "$archivo")
                        hash=$(md5 -q "$archivo")
                        printf "| %-30s | %-30s | %-30s\n" "$nombre" "$timestamp" "$hash" >> "$releaseName"/"$releaseNote"
                    fi
                done
            fi
        fi
    done
else
    echo "The directory does not exist: $directory"
fi

echo "[OK] $releaseNote"

echo "Packaging..."
tar -zcvf "$releaseName"_windows.tar.gz "$releaseName"
tar="$releaseName"_windows.tar.gz
echo "Ready! :) --> $tar"


