# ASB API Converting Bulletin Data to Realtime Database Trees and Database Interaction

## Set Up

1) Install yargs and ts-node
   yargs: npm i yargs, npm install @types/yargs
   ts-node: npm install -g typescript, npm install -g ts-node
2) CD into step95-2020/functions/src/scripts

## To Run

1) Locate the local file path for the input bulletin JSON file 
2) Run npm run lint 
   Note: Warnings will not stop the code working. Ignore warnings about body parser being deprecated
3) Run npm run build
4) Run the command: ts-node --project ../../tsconfig.json converter.ts --inputPath <file path for input file>
   NOTE: You are in the source folder of step95-2020/functions. If you want to move up a directory, remember to do ../ before the file name (same for output path)
         Also, the input should be the JSON representation of the bulletin data and the output is in JSON format - make sure your output file ends in .json.
5) If the script is successful, the console should print that all six trees have been uploaded. You should see the new data in the realtime database UI. 
