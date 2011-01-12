

word="A R A H O W"

convert \
  -size '300x50' \
  -strokewidth 1 \
  -gravity center \
  -fill '#ffa500' \
  -family 'monoco' \
  -pointsize 42 \
  -bordercolor white \
  -border 5 \
  -annotate "0x0" "$word" \
  -wave '3x50' \
  -implode 0.2 \
  -strokewidth 10 \
  -draw 'line 5 25 295 25' \
  -draw 'line 5 35 295 35' \
  xc:white jpg:- > raptcha.jpg 

open raptcha.jpg 

  #-draw 'point 3,2' \
