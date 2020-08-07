# ASB API Converting Bulletin Data to Realtime Database Trees and Database Interaction

## Set Up

1) Install yargs and ts-node
   yargs: npm i yargs, npm install @types/yargs
   ts-node: npm install -g typescript, npm install -g ts-node
2) CD into step95-2020/functions/src/scripts

## To Run As A Script

1) Locate the local file path for the input bulletin JSON file 
2) Run npm run lint 
   Note: Warnings will not stop the code working. Ignore warnings about body parser being deprecated
3) Run npm run build
4) Run the command: ts-node --project ../../tsconfig.json scriptConverter.ts --inputPath <file path for input file>
5)NOTE: You are in the scripts folder of step95-2020/functions/src. The input path should be a JSON representation
   of the bulletin data. 
6) If the script is successful, the console should print that all trees have been uploaded. You should see the new data in the realtime database UI. 

## To Run on the UI
1) Navigate to step95-2020.web.app and log in as admin to home page
2) Select and input file into the upload box
3) If the code is sucessful, the trees will all be updated and you can view them in the realtime database UI. 

