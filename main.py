import pandas as pd
import os
#setup stripe
import stripe
from dotenv import load_dotenv

load_dotenv()
stripe.api_key = os.getenv("STRIPE_TOKEN")
stripe.api_version = "2020-08-27"

#Lists for caveman recursive searching
spacelist=[]
checkedSpaces=[]
checkedPrints=[]
fingerprintlist=[]
finaldict={}

d = []

def initsearch():
    # Takes a cc fingerprint via input
    firstprint=input("First fingerprint")
    # Create a querystring and search stripe for that query
    initquery = "payment_method_details.card.fingerprint:'"+firstprint+"'"
    firstList = stripe.Charge.search(query=initquery)
    #paginate the Stripe object returned from query and append every SPACE associated with the FINGERPRINT provided
    for space in firstList.auto_paging_iter():
        if len(space.metadata) != 0:
            if space.metadata.space_id not in spacelist:
                spacelist.append(space.metadata.space_id)
    #Call next function and pass a list of spaces
    fPrintRetriever(spacelist)

def fPrintRetriever(Spaces):
    # For each space in our SpaceList
    for space in Spaces:
        # Ensure the space has not been checked, then add it to our CHECKED spaces list
        if space not in checkedSpaces:
            print('checking: ',space)
            checkedSpaces.append(space)

            # Build a new querystring that searches for the SPACE by metadata
            query = "metadata['space_id']:'" + space + "'"
            printsRetrieved = stripe.Charge.search(query=str(query))

            # add the space to our final dictionary and build an empty list
            finaldict[space] = []

            # for each charge in the space, paginate over the object and retrieve the CC fingerprint
            for fPrint in printsRetrieved.auto_paging_iter():
                curPrint = fPrint.payment_method_details.card.fingerprint

                # if the fingerprint is not associated to the space, associate it via our dictionary, AND add it to our FINGERPRINT list
                if curPrint not in finaldict[space]:
                    fingerprintlist.append(curPrint)
                    finaldict[space].append(curPrint)

    # if our FINGERPRINT list is longer than our CHECKED fingerprints, we have more fingerprints to search
    if len(fingerprintlist) >len(checkedPrints):
        spaceRetriever(fingerprintlist)

def spaceRetriever(fPrintList):

    # For each FINGERPRINT in our list, ensure we have not checked that fingerprint
    for fPrint in fPrintList:
        if fPrint not in checkedPrints:

            # Add the fingerprint to our CHECKED list
            checkedPrints.append(fPrint)

            # Build a new querystring to search the fingerprints
            printQuery = "payment_method_details.card.fingerprint:'"+fPrint+"'"
            spacesRetrieved = stripe.Charge.search(query=str(printQuery))

            # For each charge associated with that fingerprint, paginate over the object and retrieve the SPACE metadata
            for space in spacesRetrieved.auto_paging_iter():
                # IF the space metadata is not in our SPACE list, add it
                if len(space.metadata) != 0:
                    if space.metadata.space_id not in spacelist:
                        spacelist.append(space.metadata.space_id)

    #IF our space list is longer than our CHECKED spaces list, we have more searches to make
    if len(spacelist)>len(checkedSpaces):
        fPrintRetriever(spacelist)

# Starts our initial search and prints the final dictionary when we exhaust all SPACES and FINGERPRINTS associated with the origin FINGERPRINT
initsearch()
for space in finaldict:
    d.append(("https://internal.signalwire.com/spaces/"+space, finaldict[space]))
    print("https://internal.signalwire.com/spaces/" + space, finaldict[space])


df = pd.DataFrame(d, columns=('Space', 'fingerprint'))
df.to_csv('fingerprints.csv', index=False, encoding='utf-8')